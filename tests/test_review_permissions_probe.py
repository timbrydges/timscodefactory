import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from botocore.exceptions import ClientError
from factory_runtime import review_permissions_probe as probe
from factory_state.model import StateError


class ProbeTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name)
        (self.root/'BUILD.json').write_text(json.dumps({'source_commit':'a'*40}))
        self.event={'kind':'bounded_review_data_read_probe','source_commit':'a'*40,'nonce':'b'*64}
        self.calls=[];self.configure('builder')

    def configure(self,role):
        self.role=role;name=probe.NAME if role=='controller' else 'tims-factory-'+role
        iam=probe.EXECUTION_ROLE if role=='controller' else probe.EXECUTION_ROLES[role]
        self.env={'FACTORY_REVIEW_PERMISSION_PROBE_ENABLED':'true','FACTORY_REVIEW_PERMISSION_PROBE_ROLE':role,
            'FACTORY_BOUNDED_REVIEW_ENABLED':'false','FACTORY_BOUNDED_CONTROLLER_ENABLED':'false',
            'AWS_REGION':probe.REGION,'AWS_LAMBDA_FUNCTION_NAME':name}
        self.context=SimpleNamespace(invoked_function_arn=f'arn:aws:lambda:{probe.REGION}:{probe.ACCOUNT}:function:{name}:1')
        self.sts=SimpleNamespace(get_caller_identity=lambda:{'Account':probe.ACCOUNT,
            'Arn':f'arn:aws:sts::{probe.ACCOUNT}:assumed-role/{iam}/fixture'})

    def read(self,**args):
        self.calls.append(args)
        if args['Key']['PK']['S'].endswith('#unapproved'):
            raise ClientError({'Error':{'Code':'AccessDeniedException','Message':'fixture'}},'GetItem')
        return {}

    def run_probe(self,read=None):
        db=SimpleNamespace(get_item=read or self.read)
        with patch.object(probe,'_aws_session',return_value=object()),\
                patch.object(probe,'client',side_effect=lambda s,n:{'sts':self.sts,'dynamodb':db}[n]):
            return probe.dispatch(self.event,self.context,root=self.root,env=self.env)

    def test_all_four_roles_only_read_exact_keys_and_return_no_authority(self):
        for role in (*probe.EXECUTION_ROLES,'controller'):
            self.configure(role);self.calls=[];result=self.run_probe()
            self.assertEqual(result['status'],'READ_ONLY_DATA_ACCESS_VERIFIED')
            self.assertFalse(result['gate_authority']);self.assertEqual(result['writes'],0)
            self.assertEqual(result['provider_calls'],0);self.assertEqual(result['signatures'],0)
            claims=[x['Key']['PK']['S'] for x in self.calls if x['TableName']==probe.TABLE]
            expected=[f'BOUNDED_REVIEW#002#ROLE#{r}' for r in (probe.EXECUTION_ROLES if role=='controller' else (role,))]
            self.assertEqual(claims,expected+['BOUNDED_REVIEW#002#ROLE#unapproved'])
            self.assertTrue(all(x['ConsistentRead'] for x in self.calls))

    def test_disabled_has_no_file_or_client_io(self):
        self.env['FACTORY_REVIEW_PERMISSION_PROBE_ENABLED']='false'
        with patch.object(probe,'_read') as read,patch.object(probe,'_aws_session') as aws:
            with self.assertRaises(StateError):probe.dispatch(None,None,root=self.root,env=self.env)
            read.assert_not_called();aws.assert_not_called()

    def test_paid_flag_or_changed_event_or_mutable_version_reject_before_clients(self):
        with patch.object(probe,'_aws_session') as aws:
            self.env['FACTORY_BOUNDED_REVIEW_ENABLED']='true'
            with self.assertRaises(StateError):probe.dispatch(self.event,self.context,root=self.root,env=self.env)
            self.env['FACTORY_BOUNDED_REVIEW_ENABLED']='false';self.event['extra']='value'
            with self.assertRaises(StateError):probe.dispatch(self.event,self.context,root=self.root,env=self.env)
            self.event.pop('extra');self.context.invoked_function_arn=self.context.invoked_function_arn.rsplit(':',1)[0]+':$LATEST'
            with self.assertRaises(StateError):probe.dispatch(self.event,self.context,root=self.root,env=self.env)
            aws.assert_not_called()

    def test_existing_claim_does_not_leak_contents_or_continue(self):
        def read(**args):
            if args['TableName']==probe.TABLE:return {'Item':{'sensitive':'not returned'}}
            return self.read(**args)
        with self.assertRaises(StateError) as caught:self.run_probe(read)
        self.assertNotIn('sensitive',str(caught.exception))
        self.assertEqual(len(self.calls),2)

    def test_missing_denial_or_unrelated_error_is_not_a_pass(self):
        with self.assertRaises(StateError):self.run_probe(lambda **_: {})
        def unavailable(**_):raise ClientError({'Error':{'Code':'ThrottlingException'}},'GetItem')
        with self.assertRaises(StateError):self.run_probe(unavailable)

    def test_wrong_identity_stops_before_reads(self):
        self.sts.get_caller_identity=lambda:{'Account':probe.ACCOUNT,'Arn':'wrong'}
        with self.assertRaises(StateError):self.run_probe()
        self.assertEqual(self.calls,[])
