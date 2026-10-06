import hashlib
import json
from unittest.mock import Mock
import unittest
from factory_runtime.handoff003_dispatcher import run,CONFIG,NAME,ARN
from factory_runtime.handoff003_attempts import TABLE,key
from factory_runtime.handoff003_packets import TASK
from factory_runtime.handoff003_receipts import sha
from factory_state.scope import canonical
from factory_state.model import StateError
import test_handoff003_dispatch as fixtures


class DispatcherTests(unittest.TestCase):
    def setUp(self):
        self.f=fixtures.DispatchTests();self.f.setUp();self.addCleanup(self.f.doCleanups)
        self.config={'source_commit':'a'*40,'pin':self.f.pin,'candidate_commit':'b'*40,'test_proof':None}
        raw=canonical(self.config);(self.f.f.root/CONFIG).write_bytes(raw)
        digest=hashlib.sha256(raw).hexdigest()
        self.event={'kind':'handoff003_dispatch_once','source_commit':'a'*40,'dispatch_sha256':digest}
        self.env={'FACTORY_HANDOFF003_DISPATCH_ENABLED':'true','FACTORY_HANDOFF003_DISPATCH_SHA256':digest,
            'AWS_REGION':'ca-central-1','AWS_LAMBDA_FUNCTION_NAME':NAME}
        self.context=Mock(invoked_function_arn=ARN+'1');self.context.get_remaining_time_in_millis.return_value=240000
        self.sts=Mock();self.sts.get_caller_identity.return_value={'Account':'666730517561',
            'Arn':'arn:aws:sts::666730517561:assumed-role/'+NAME+'/fixture'}
        self.clients=Mock(return_value=(self.sts,self.f.db,self.f.lam))
        self.f.db.get_item.return_value={}
    def call(self,**kw):
        return run(**{**dict(event=self.event,context=self.context,root=self.f.f.root,env=self.env,
            clock=lambda:self.f.f.fixture.now,clients=self.clients),**kw})
    def test_real_composition_dispatches_signed_stage_once(self):
        self.assertEqual(self.call()['status'],'SIGNED_RESULT_OBSERVED')
        self.assertEqual(self.call()['status'],'DISPATCH_CONSUMED_OR_UNCERTAIN')
        self.f.lam.invoke.assert_called_once()
    def test_disabled_wrong_event_alias_and_short_deadline_never_touch_aws(self):
        with self.assertRaises(StateError):self.call(env={})
        with self.assertRaises(StateError):self.call(event={})
        self.context.invoked_function_arn=ARN+'latest'
        with self.assertRaises(StateError):self.call()
        self.context.invoked_function_arn=ARN+'1';self.context.get_remaining_time_in_millis.return_value=180000
        with self.assertRaises(StateError):self.call()
        self.clients.assert_not_called()
    def test_read_failure_never_becomes_absent_or_invokes(self):
        self.f.db.get_item.side_effect=TimeoutError()
        with self.assertRaises(TimeoutError):self.call()
        self.f.lam.invoke.assert_not_called();self.f.db.put_item.assert_not_called()
    def test_qa_without_independent_tests_never_touches_aws(self):
        fixture=self.f.f.fixture;fixture.execute('inspector')
        allowance,args,_=fixture.setup_role('qa')
        self.f.f.doc.update(role='qa',allowance=allowance,qualification=args['qualification'],readiness=args['readiness'],
            predecessors=fixture.chain,predecessor_request_digests=fixture.requests,candidate_commit='b'*40,
            credential={'kind':'secretsmanager','secret_arn':fixtures.fixtures.entry.SECRETS['qa'],
                'version_id':'b'*32,'json_key':'api_key'})
        self.f.f.env['FACTORY_HANDOFF003_ROLE']='qa';self.f.f.save()
        self.config['pin'].update(role='qa',activation_sha256=self.f.f.env['FACTORY_HANDOFF003_ACTIVATION_SHA256'])
        raw=canonical(self.config);(self.f.f.root/CONFIG).write_bytes(raw)
        digest=hashlib.sha256(raw).hexdigest();self.env['FACTORY_HANDOFF003_DISPATCH_SHA256']=digest
        self.event['dispatch_sha256']=digest
        with self.assertRaisesRegex(StateError,'Independent candidate test evidence'):self.call()
        self.clients.assert_not_called()
    def test_durable_result_recovered_without_repeat_invocation(self):
        self.call();envelope=self.f.envelope;request=envelope['payload']['request_digest']
        attempt={**key('builder'),'task_id':{'S':TASK},'role':{'S':'builder'},'source_commit':{'S':'a'*40},
            'status':{'S':'COMPLETE'},'reservation_status':{'S':'HELD'},'reserved_micro_usd':{'N':'250000'},
            'actual_micro_usd':{'N':str(envelope['payload']['actual_micro_usd'])},
            'request_digest':{'S':request},'output_digest':{'S':sha(canonical(envelope))}}
        row={'status':{'S':'COMPLETE'},'signed_receipt':{'S':canonical(envelope).decode()},
            'output_digest':{'S':sha(canonical(envelope))},'request_digest':{'S':request}}
        self.f.db.get_item.side_effect=lambda **kw:({'Item':attempt if kw['TableName']==TABLE else row}
            if kw['Key']['PK']['S'].endswith('builder') else {})
        result=self.call()
        self.assertEqual(result['status'],'STAGE_ALREADY_COMPLETE')
        self.assertEqual(result['envelope'],envelope);self.f.lam.invoke.assert_called_once()
        row['output_digest']['S']='sha256:'+'0'*64
        with self.assertRaises(StateError):self.call()
        self.f.lam.invoke.assert_called_once()
