import base64
import io
import copy
from types import SimpleNamespace
import unittest
from unittest.mock import Mock
from factory_runtime.handoff004_dispatch import dispatch_once
from factory_runtime.handoff004_attempts import key
from factory_runtime.handoff004_packets import TASK
from factory_runtime.handoff004_receipts import sha
from factory_state.model import StateError
from factory_state.scope import canonical
import test_handoff004_entrypoint as fixtures

class DispatchTests(unittest.TestCase):
    def setUp(self):
        self.f=fixtures.HandoffEntrypointTests();self.f.setUp();self.addCleanup(self.f.doCleanups)
        self.f.fixture.execute('builder');self.envelope=self.f.fixture.chain['builder']
        meta=SimpleNamespace(config=SimpleNamespace(retries={'total_max_attempts':1}))
        self.db=Mock();self.db.meta=meta;self.lam=Mock();self.lam.meta=meta
        self.pin={'role':'builder','version_arn':self.f.context.invoked_function_arn,
            'source_commit':'a'*40,'activation_sha256':self.f.env['FACTORY_HANDOFF004_ACTIVATION_SHA256'],
            'code_sha256':base64.b64encode(b'0'*32).decode()}
        self.lam.get_function_configuration.return_value={'CodeSha256':self.pin['code_sha256'],'Version':'1',
            'FunctionName':'tims-factory-handoff-004-builder','Handler':'factory_runtime.handoff004_entrypoint.handler',
            'Environment':{'Variables':{k:v for k,v in self.f.env.items() if k.startswith('FACTORY_')}}}
        self.lam.invoke.side_effect=lambda **kw:{'Payload':io.BytesIO(canonical(self.envelope))}
        self.claimed=False
        def put(**kw):
            if self.claimed:raise RuntimeError('Already claimed')
            self.claimed=True
        self.db.put_item.side_effect=put
        self.context=dict(attempts={r:None for r in ('builder','inspector','qa')},envelopes={},
            root=self.f.root,trusted_keys=self.f.fixture.keys,source_commit='a'*40,candidate_commit='b'*40,
            request_digests={},verify_executed_tests=lambda *_:True)
    def run_once(self,**changes):
        return dispatch_once(**{**dict(context=self.context,pin=self.pin,activation_root=self.f.root,
            db=self.db,lam=self.lam,clock=lambda:self.f.fixture.now,enabled=True),**changes})
    def test_valid_scope_invokes_once_and_permanent_claim_blocks_duplicate(self):
        self.assertEqual(self.run_once()['status'],'SIGNED_RESULT_OBSERVED')
        self.assertEqual(self.run_once()['status'],'DISPATCH_CONSUMED_OR_UNCERTAIN')
        self.lam.invoke.assert_called_once();self.db.update_item.assert_called_once()
        values=self.db.update_item.call_args.kwargs['ExpressionAttributeValues']
        self.assertEqual(values[':receipt']['S'].encode(),canonical(self.envelope))
    def test_disabled_alias_changed_code_or_trust_never_claim(self):
        with self.assertRaises(StateError):self.run_once(enabled=False)
        with self.assertRaises(StateError):self.run_once(pin={**self.pin,'version_arn':self.pin['version_arn'].rsplit(':',1)[0]+':latest'})
        with self.assertRaises(StateError):self.run_once(context={**self.context,'trusted_keys':{}})
        self.lam.get_function_configuration.return_value['CodeSha256']='changed'
        with self.assertRaises(StateError):self.run_once()
        self.db.put_item.assert_not_called();self.lam.invoke.assert_not_called()
    def test_unknown_claim_and_timeout_never_retry(self):
        self.db.put_item.side_effect=TimeoutError()
        self.assertEqual(self.run_once()['status'],'DISPATCH_CONSUMED_OR_UNCERTAIN')
        self.lam.invoke.assert_not_called()
        self.db.put_item.side_effect=None;self.lam.invoke.side_effect=TimeoutError()
        self.assertEqual(self.run_once()['status'],'DISPATCH_OUTCOME_UNCERTAIN_NO_RETRY')
        self.lam.invoke.assert_called_once();self.db.update_item.assert_not_called()
    def test_signed_result_completion_failure_keeps_uncertain_dispatch(self):
        self.db.update_item.side_effect=TimeoutError()
        self.assertEqual(self.run_once()['status'],'DISPATCH_OUTCOME_UNCERTAIN_NO_RETRY')
        self.assertEqual(self.run_once()['status'],'DISPATCH_CONSUMED_OR_UNCERTAIN')
        self.lam.invoke.assert_called_once()
    def test_sdk_retries_rejected_before_claim(self):
        self.lam.meta.config.retries={'total_max_attempts':2}
        with self.assertRaises(StateError):self.run_once()
        self.db.put_item.assert_not_called()

    def test_unsigned_runtime_output_does_not_complete_dispatch(self):
        self.lam.invoke.side_effect=lambda **kw:{'Payload':io.BytesIO(b'{"status":"untrusted"}')}
        self.assertEqual(self.run_once()['status'],'DISPATCH_OUTCOME_UNCERTAIN_NO_RETRY')
        self.db.update_item.assert_not_called()
        self.assertEqual(self.run_once()['status'],'DISPATCH_CONSUMED_OR_UNCERTAIN')
        self.lam.invoke.assert_called_once()

    def test_safe_provider_failure_is_durable_terminal_and_not_a_receipt(self):
        result={'status':'HANDOFF_FAILED_NO_RETRY','role':'builder','failure_stage':'provider',
            'failure_category':'timeout','http_status':None,'attempt_reusable':False,
            'reservation_status':'HELD','gate_authority':False}
        self.lam.invoke.side_effect=lambda **kw:{'Payload':io.BytesIO(canonical(result))}
        self.assertEqual(self.run_once()['status'],'DISPATCH_FAILED_NO_RETRY')
        values=self.db.update_item.call_args.kwargs['ExpressionAttributeValues']
        self.assertEqual(values[':failed'],{'S':'FAILED'})
        self.assertEqual(values[':failure'],{'S':'timeout'})
        self.assertNotIn(':receipt',values)
        self.assertEqual(self.run_once()['status'],'DISPATCH_CONSUMED_OR_UNCERTAIN')
        self.lam.invoke.assert_called_once()

    def test_untrusted_failure_details_are_not_persisted(self):
        from factory_runtime.handoff004_dispatch import _provider_failure
        good={'status':'HANDOFF_FAILED_NO_RETRY','role':'builder','failure_stage':'provider',
            'failure_category':'http_status','http_status':503,'attempt_reusable':False,
            'reservation_status':'HELD','gate_authority':False}
        self.assertEqual(_provider_failure(good,'builder'),'http_status_503')
        for changes in ({'http_status':True},{'http_status':600},{'http_status':'503 secret'},
                {'failure_category':'private detail'},{'response':'secret'},{'role':'qa'},{'gate_authority':True}):
            with self.subTest(changes=changes):self.assertIsNone(_provider_failure({**good,**changes},'builder'))

    def test_failure_persistence_error_still_cannot_repeat_worker(self):
        value={'status':'HANDOFF_FAILED_NO_RETRY','role':'builder','failure_stage':'provider',
            'failure_category':'unknown','http_status':None,'attempt_reusable':False,
            'reservation_status':'HELD','gate_authority':False}
        self.lam.invoke.side_effect=lambda **kw:{'Payload':io.BytesIO(canonical(value))}
        self.db.update_item.side_effect=TimeoutError('unobserved write')
        self.assertEqual(self.run_once()['status'],'DISPATCH_OUTCOME_UNCERTAIN_NO_RETRY')
        self.assertEqual(self.run_once()['status'],'DISPATCH_CONSUMED_OR_UNCERTAIN')
        self.lam.invoke.assert_called_once()

    def test_three_role_dispatch_chain_then_terminal_no_invoke(self):
        # Real synthetic signatures and owner scopes; only AWS/provider I/O is mocked.
        claims=set()
        def claim(**kw):
            identity=kw['Item']['PK']['S']
            if identity in claims:raise RuntimeError('Consumed')
            claims.add(identity)
        self.db.put_item.side_effect=claim
        for role in ('builder','inspector','qa'):
            if role!='builder':
                allowance,args,_=self.f.fixture.setup_role(role)
                self.f.doc.update(role=role,allowance=allowance,qualification=args['qualification'],
                    readiness=args['readiness'],predecessors=copy.deepcopy(self.context['envelopes']),
                    predecessor_request_digests=dict(self.context['request_digests']),candidate_commit='b'*40,
                    credential=({'kind':'lambda_execution_role'} if role=='inspector' else {
                        'kind':'secretsmanager','secret_arn':fixtures.entry.SECRETS['qa'],
                        'version_id':'b'*32,'json_key':'api_key'}))
                self.f.env['FACTORY_HANDOFF004_ROLE']=role;self.f.save()
                self.f.fixture.execute(role);self.envelope=self.f.fixture.chain[role]
                self.pin.update(role=role,activation_sha256=self.f.env['FACTORY_HANDOFF004_ACTIVATION_SHA256'],
                    version_arn='arn:aws:lambda:ca-central-1:666730517561:function:tims-factory-handoff-004-'+role+':1')
                self.lam.get_function_configuration.return_value.update(
                    FunctionName='tims-factory-handoff-004-'+role,
                    Environment={'Variables':{k:v for k,v in self.f.env.items() if k.startswith('FACTORY_')}})
            result=self.run_once()
            self.assertEqual(result['status'],'SIGNED_RESULT_OBSERVED')
            self.assertFalse(result['gate_authority'])
            envelope=result['envelope'];request=envelope['payload']['request_digest']
            self.context['envelopes'][role]=envelope;self.context['request_digests'][role]=request
            self.context['attempts'][role]={**key(role),'task_id':{'S':TASK},'role':{'S':role},
                'source_commit':{'S':'a'*40},'status':{'S':'COMPLETE'},'reservation_status':{'S':'HELD'},
                'reserved_micro_usd':{'N':'250000'},'actual_micro_usd':{'N':str(envelope['payload']['actual_micro_usd'])},
                'request_digest':{'S':request},'output_digest':{'S':sha(canonical(envelope))}}
        self.assertEqual(self.run_once()['status'],'COMPLETED_NO_DISPATCH')
        self.assertEqual(self.lam.invoke.call_count,3)
        self.assertEqual(self.db.update_item.call_count,3)
        self.assertEqual(len(claims),3)
