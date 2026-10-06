"""Real signed scopes and durable Moto claims; provider and KMS peers are fixtures."""
import base64
from dataclasses import asdict
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import test_review_provider_execution as providers
import test_review_signing as signing
from factory_runtime.review_role_runtime import BoundedReviewRoleRuntime
from factory_runtime.review_provider_scope import FACTORY, TASK
from factory_state.model import StateError
from factory_state.scope import SignedScopeStore


@unittest.skipIf(providers.mock_aws is None, 'Requires moto[dynamodb]')
class BoundedRoleTests(unittest.TestCase):
    def setUp(self):
        self.p = providers.BackendTests(); self.p.setUp(); self.addCleanup(self.p.doCleanups)
        self.k = signing.ReviewSigningTests(); self.k.setUp(); self.addCleanup(self.k.doCleanups)
        self.k.role = 'builder'
        self.p.keys[self.k.identity] = self.k.keys[self.k.identity]
        self.kms = SimpleNamespace(get_public_key=self.k.get_public_key, sign=self.k.sign,
            meta=SimpleNamespace(endpoint_url='https://kms.ca-central-1.amazonaws.com',
                config=SimpleNamespace(retries={'total_max_attempts': 1})))
        self.sts = SimpleNamespace(get_caller_identity=self.k.get_caller_identity,
            meta=SimpleNamespace(endpoint_url='https://sts.ca-central-1.amazonaws.com',
                config=SimpleNamespace(retries={'total_max_attempts': 1})))
        self.p.db.create_table(TableName='tims-factory-role-executions',
            KeySchema=[{'AttributeName':'PK','KeyType':'HASH'},{'AttributeName':'SK','KeyType':'RANGE'}],
            AttributeDefinitions=[{'AttributeName':k,'AttributeType':'S'} for k in ('PK','SK')],
            BillingMode='PAY_PER_REQUEST')
        self.event = {'schema_version':'1.0','factory_id':FACTORY,'task_id':TASK,
            'dispatch_id':self.p.dispatch,'worker_id':'bounded-review-controller',
            'request':asdict(self.p.request),
            'input_base64':base64.b64encode(self.p.prepared.input_bytes).decode()}

    def runtime(self, enabled=True):
        return BoundedReviewRoleRuntime(backend=self.p.backend,kms=self.kms,sts=self.sts,
            execution_table='tims-factory-role-executions',enabled=enabled)

    def test_signed_output_and_duplicate_delivery_use_one_provider_send(self):
        peer=providers.Connection(providers.Response(providers.response_for(self.p.prepared)))
        with patch.object(providers.wire.http.client,'HTTPSConnection',return_value=peer) as connect:
            result=self.runtime().handle(self.event)
            self.assertEqual(self.runtime().handle(self.event),result)
            self.assertEqual(connect.call_count,1)
        SignedScopeStore('unused',None,self.p.keys)._verify(result['payload'],
            base64.b64decode(result['signature_base64']),self.k.identity,self.p.now)
        self.assertEqual(len(self.k.sign_calls),1)
        self.assertEqual(self.p.row()['status'],{'S':'COMPLETE'})

    def test_wrong_signing_identity_stops_before_claims_and_credential_read(self):
        self.k.wrong_session=True
        with self.assertRaises(StateError):self.runtime().handle(self.event)
        self.assertIsNone(self.p.row());self.p.loader.assert_not_called()
        self.assertEqual(self.p.db.scan(TableName='tims-factory-role-executions')['Count'],0)
        self.assertEqual(self.k.sign_calls,[])

    def test_revocation_during_preflight_leaves_claims_unused(self):
        self.k.public_hook=lambda:self.p.keys.pop(self.k.identity)
        with self.assertRaises(StateError):self.runtime().handle(self.event)
        self.assertIsNone(self.p.row());self.p.loader.assert_not_called()

    def test_disabled_or_changed_event_never_reads_signing_key(self):
        with patch.object(self.kms,'get_public_key',side_effect=AssertionError('unexpected key read')):
            with self.assertRaises(StateError):self.runtime(False).handle(self.event)
            for change in ({'task_id':'old-task'},{'worker_id':'other'},{'dispatch_id':'f'*64},
                           {'input_base64':'e30='},{'configuration':{}}):
                with self.subTest(change=change),self.assertRaises(StateError):
                    self.runtime().handle({**self.event,**change})
        self.assertIsNone(self.p.row());self.p.loader.assert_not_called()

    def test_uncertain_send_is_not_repeated_by_new_runtime(self):
        with patch.object(providers.wire.http.client,'HTTPSConnection',
                return_value=providers.Connection(error=TimeoutError('fixture'))) as connect:
            with self.assertRaises(StateError):self.runtime().handle(self.event)
            with self.assertRaises(StateError):self.runtime().handle(self.event)
            self.assertEqual(connect.call_count,1)
        self.assertEqual(self.p.row()['status'],{'S':'STARTED'})
        self.assertEqual(self.k.sign_calls,[])

    def test_retrying_or_redirected_signing_sdk_rejected_without_io(self):
        self.kms.meta.config.retries['total_max_attempts']=2
        with self.assertRaises(StateError):self.runtime()
        self.kms.meta.config.retries['total_max_attempts']=1
        self.sts.meta.endpoint_url='https://untrusted.invalid'
        with self.assertRaises(StateError):self.runtime()
