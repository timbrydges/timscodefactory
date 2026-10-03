import base64
import copy
import hashlib
import json
import unittest
from unittest.mock import Mock,patch

import test_pilot002_adapter as adapters
import test_pilot002_transport as transports
from factory_runtime import pilot002_entrypoint as p
from factory_state.model import OWNER_IDENTITY,StateError
from factory_state.scope import canonical
from factory_state.signers import public_key_der


class EntrypointTests(unittest.TestCase):
    def setUp(self):
        self.fixtures=adapters.AdapterTests();self.fixtures.setUp()

    def setup_role(self,role='builder'):
        _,_,_,q,envelope,args,db=self.fixtures.setup_role(role)
        epoch=int(self.fixtures.now.timestamp());pem=self.fixtures.keys[OWNER_IDENTITY]
        registry={'schema_version':'1.0','enabled':True,'signers':[{'identity':OWNER_IDENTITY,
            'public_key_pem':pem.decode(),'fingerprint':'sha256:'+hashlib.sha256(public_key_der(pem)).hexdigest(),
            'enrollment_commit':'d'*40,'not_before':epoch-1,'expires_at':epoch+3600,'revoked':False}]}
        route={'kind':'lambda_execution_role'} if role=='inspector' else {'kind':'secretsmanager',
            'secret_arn':'arn:aws:secretsmanager:ca-central-1:666730517561:secret:fixture-'+role,
            'version_id':'a'*32,'json_key':None}
        self.doc={'schema_version':'1.0','role':role,'source_commit':'c'*40,'qualification':q,
            'readiness':args['readiness'],'signer_registry':registry,'credential':route,
            'builder_response_base64':base64.b64encode(args['builder_response']).decode() if role!='builder' else None,
            'candidate_commit':args.get('candidate_commit')}
        self.env={'FACTORY_PILOT002_EXECUTION_ENABLED':'true','FACTORY_PILOT002_ROLE':role,
            'AWS_REGION':p.REGION,'AWS_LAMBDA_FUNCTION_NAME':'tims-factory-pilot-002-'+role}
        self.context=Mock(invoked_function_arn='arn:aws:lambda:ca-central-1:666730517561:function:tims-factory-pilot-002-'+role)
        self.context.get_remaining_time_in_millis.return_value=150000
        self.event={'kind':'pilot002_run_once','allowance':envelope}
        self.args={'root':args['root'],'env':self.env,'clock':self.fixtures.clock}
        self.db=db;self.session=Mock();self.session.get_credentials.return_value.get_frozen_credentials.return_value=transports.AWS
        self.secret=Mock();self.secret.get_secret_value.return_value={'ARN':route.get('secret_arn'),
            'VersionId':route.get('version_id'),'SecretString':transports.KEY}
        self.connection=transports.Connection(transports.Response(canonical(self.fixtures.fixtures.response(role))))
        self.encode()

    def encode(self):
        self.activation=canonical(self.doc)
        self.env['FACTORY_PILOT002_ACTIVATION_SHA256']=hashlib.sha256(self.activation).hexdigest()

    def read(self,root,name,limit):
        return self.activation if name==p.ACTIVATION else canonical({'source_commit':'c'*40})

    def run_event(self):
        return p.dispatch(self.event,self.context,**self.args)

    def test_three_roles_use_real_signed_workflow_and_never_repeat(self):
        for role in ('builder','inspector','qa'):
            self.setup_role(role)
            with self.subTest(role=role),patch.object(p,'_read',side_effect=self.read),patch.object(p,'_aws_session',return_value=self.session),\
                    patch.object(p,'_client',side_effect=lambda session,service:self.db if service=='dynamodb' else self.secret),\
                    patch.object(transports.p.http.client,'HTTPSConnection',return_value=self.connection):
                result=self.run_event()
                self.assertEqual(result['status'],'PILOT002_COMPLETED_UNSIGNED')
                self.assertFalse(result['gate_authority']);self.assertEqual(len(self.connection.calls),1)
                self.assertEqual(self.fixtures.events,['claim','complete'])
                with self.assertRaises(StateError):self.run_event()
                self.assertEqual(len(self.connection.calls),1)
                self.assertEqual(self.secret.get_secret_value.call_count,0 if role=='inspector' else 1)
                if role!='inspector':
                    self.secret.get_secret_value.assert_called_once_with(SecretId=self.doc['credential']['secret_arn'],VersionId='a'*32)

    def test_disabled_rejects_before_read_or_sdk(self):
        with patch.object(p,'_read') as read,patch.object(p,'_aws_session') as aws:
            for env in ({},{'FACTORY_PILOT002_EXECUTION_ENABLED':True},{'FACTORY_PILOT002_EXECUTION_ENABLED':'false'}):
                with self.assertRaisesRegex(StateError,'disabled'):p.dispatch(None,None,root=None,env=env,clock=None)
            read.assert_not_called();aws.assert_not_called()

    def test_bad_signature_or_invocation_overrides_create_no_clients(self):
        self.setup_role()
        original=copy.deepcopy(self.event)
        for event in ({**original,'qualification':self.doc['qualification']},
                      {**original,'kind':'pilot002_runtime_probe'},
                      {**original,'allowance':{**original['allowance'],'signature':'A'*88}}):
            self.event=event
            with self.subTest(event=event),patch.object(p,'_read',side_effect=self.read),patch.object(p,'_aws_session') as aws:
                with self.assertRaises(StateError):self.run_event()
                aws.assert_not_called()

    def test_wrong_function_region_alias_or_short_timeout_is_rejected(self):
        self.setup_role()
        original=self.context.invoked_function_arn
        for arn in (original+':1',original.replace('666730517561','111111111111'),original.replace('builder','qa')):
            self.context.invoked_function_arn=arn
            with patch.object(p,'_read') as read:
                with self.assertRaises(StateError):self.run_event()
                read.assert_not_called()
        self.context.invoked_function_arn=original
        self.context.get_remaining_time_in_millis.return_value=119999
        with patch.object(p,'_read') as read:
            with self.assertRaises(StateError):self.run_event()
            read.assert_not_called()

    def test_activation_digest_role_source_enrollment_and_route_are_pinned(self):
        mutations=(lambda d:d.update(role='qa'),lambda d:d.update(source_commit='e'*40),
            lambda d:d['signer_registry']['signers'][0].update(revoked=True),
            lambda d:d['credential'].update(version_id='AWSCURRENT'),
            lambda d:d['credential'].update(secret_arn='arn:aws:secretsmanager:us-east-1:666730517561:secret:fixture'),
            lambda d:d.update(candidate_commit='a'*40),lambda d:d.update(extra='override'))
        for mutate in mutations:
            self.setup_role();mutate(self.doc);self.encode()
            with patch.object(p,'_read',side_effect=self.read),patch.object(p,'_aws_session') as aws:
                with self.assertRaises(StateError):self.run_event()
                aws.assert_not_called()
        self.setup_role();self.activation+=b' '
        with patch.object(p,'_read',side_effect=self.read),patch.object(p,'_aws_session') as aws:
            with self.assertRaises(StateError):self.run_event()
            aws.assert_not_called()

    def test_duplicate_config_keys_rejected(self):
        self.setup_role();self.activation=self.activation[:-1]+b',"role":"qa"}'
        self.env['FACTORY_PILOT002_ACTIVATION_SHA256']=hashlib.sha256(self.activation).hexdigest()
        with patch.object(p,'_read',side_effect=self.read),patch.object(p,'_aws_session') as aws:
            with self.assertRaises(StateError):self.run_event()
            aws.assert_not_called()

    def test_secret_failure_consumes_attempt_without_sending_or_leaking(self):
        self.setup_role();self.secret.get_secret_value.side_effect=RuntimeError('sensitive-provider-detail')
        with patch.object(p,'_read',side_effect=self.read),patch.object(p,'_aws_session',return_value=self.session),\
                patch.object(p,'_client',side_effect=lambda session,service:self.db if service=='dynamodb' else self.secret),\
                patch.object(transports.p.http.client,'HTTPSConnection') as connect:
            for _ in range(2):
                with self.assertRaisesRegex(StateError,'^Pilot 002 entry point stopped; reconcile without retry$'):self.run_event()
            self.assertEqual(len(self.fixtures.rows),1)
            self.secret.get_secret_value.assert_called_once();connect.assert_not_called()

    def test_cloud_clients_use_fixed_endpoints_no_proxy_no_sdk_retries(self):
        session=Mock();p._client(session,'dynamodb');args=session.client.call_args.kwargs
        self.assertEqual(args['endpoint_url'],'https://dynamodb.ca-central-1.amazonaws.com')
        self.assertEqual(args['config'].retries,{'total_max_attempts':1});self.assertEqual(args['config'].proxies,{})
        with self.assertRaises(ValueError):p._client(session,'bedrock')


if __name__=='__main__':unittest.main()
