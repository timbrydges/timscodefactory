import base64
import io
from types import SimpleNamespace
import unittest
from unittest.mock import Mock
from factory_runtime.handoff002_dispatch import dispatch_once
from factory_state.model import StateError
from factory_state.scope import canonical
import test_handoff002_entrypoint as fixtures

class DispatchTests(unittest.TestCase):
    def setUp(self):
        self.f=fixtures.HandoffEntrypointTests();self.f.setUp();self.addCleanup(self.f.doCleanups)
        self.f.fixture.execute('builder');self.envelope=self.f.fixture.chain['builder']
        meta=SimpleNamespace(config=SimpleNamespace(retries={'total_max_attempts':1}))
        self.db=Mock();self.db.meta=meta;self.lam=Mock();self.lam.meta=meta
        self.pin={'role':'builder','version_arn':self.f.context.invoked_function_arn,
            'source_commit':'a'*40,'activation_sha256':self.f.env['FACTORY_HANDOFF002_ACTIVATION_SHA256'],
            'code_sha256':base64.b64encode(b'0'*32).decode()}
        self.lam.get_function_configuration.return_value={'CodeSha256':self.pin['code_sha256'],'Version':'1',
            'FunctionName':'tims-factory-handoff-002-builder','Handler':'factory_runtime.handoff002_entrypoint.handler',
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
