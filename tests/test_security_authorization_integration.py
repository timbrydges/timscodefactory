"""Real owner/reviewer signatures and DynamoDB records; no provider calls.

The QA prerequisite callback remains a test fixture, not live QA authority.
"""
import base64
from dataclasses import replace
from datetime import timedelta
import tempfile
import unittest
from unittest.mock import patch

from factory_runtime import pilot002_transport as wire
from factory_runtime.worker import digest
from factory_state.dispatch import DynamoDBDispatchStore
from factory_state.dynamodb import DynamoDBStateStore
from factory_state.model import CONTROLLER_IDENTITY, TaskState, Lease, StateError
from factory_state.scope import SignedScopeStore, canonical
from scripts.scope_dispatch_canary import fixture_keys, sign
import test_security_provider_backend as backend_fixtures
from test_security_provider_claims import mock_aws, NOW
from test_security_provider_scope import fixture as allowance_fixture
from test_pilot002_transport import Connection, Response, AWS


@unittest.skipIf(mock_aws is None, 'Requires moto[dynamodb]')
class SecurityAuthorizationTests(unittest.TestCase):
    def setUp(self):
        self.fixture = backend_fixtures.SecurityBackendTests()
        self.fixture.setUp(); self.addCleanup(self.fixture.doCleanups)
        self.backend = self.fixture.backend; self.backend.enabled = True
        self.db = self.fixture.claims.db
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.keys, self.private = fixture_keys(self.temp.name,
            ('tim_brydges', 'product_spec_reviewer_service'))
        self.db.create_table(TableName='security-state',
            KeySchema=[{'AttributeName':'PK','KeyType':'HASH'},{'AttributeName':'SK','KeyType':'RANGE'}],
            AttributeDefinitions=[{'AttributeName':k,'AttributeType':'S'} for k in ('PK','SK')],
            BillingMode='PAY_PER_REQUEST')
        self.states = DynamoDBStateStore('security-state', self.db)
        self.ledger = DynamoDBDispatchStore('security-state', self.db)
        self.request = self.backend.prepared.scope.request
        self.state = TaskState('tims-software-factory', 'bounded-review-004', 'SECURITY_REVIEW',
            7, NOW, CONTROLLER_IDENTITY, (Lease(self.request.lease_id, 'deep_security_reviewer',
                'deep_security_reviewer_service', NOW+timedelta(minutes=15)),))
        self.save(self.state)
        scopes = SignedScopeStore('security-state', self.db, self.keys)
        times = {'issued_at':int(NOW.timestamp())-1, 'expires_at':int(NOW.timestamp())+600}
        cap = {'kind':'capability','factory_id':self.state.factory_id,
            'objective_id':self.request.objective_id,'capability_id':self.request.capability_id,
            'contract_digest':self.request.contract_digest,'owner_identity':'tim_brydges',
            'required_evidence':'Synthetic test fixture','stop_condition':'End fixture',**times}
        scopes.approve_capability(self.state, self.request, cap,
            sign(cap, self.private['tim_brydges'], self.temp.name), now=NOW)
        review = {'kind':'scope_review','factory_id':self.state.factory_id,'task_id':self.state.task_id,
            'binding':self.ledger._binding(self.request),'reviewer_identity':'product_spec_reviewer_service',
            'verdict':'ACCEPTED','rationale':'Synthetic test fixture',**times}
        scopes.approve_task(self.state, self.request, review,
            sign(review, self.private['product_spec_reviewer_service'], self.temp.name), now=NOW)
        self.dispatch = self.ledger.enqueue(self.state, self.request,
            caller_identity=CONTROLLER_IDENTITY, now=NOW)
        self.ledger.claim(self.state, self.request, worker_id='bounded-security-controller',
                          caller_identity=CONTROLLER_IDENTITY, now=NOW)
        _, price, ready, payload = allowance_fixture()
        binding = self.backend.prepared.scope.bindings()
        price.update(binding); ready.update(binding); payload.update(binding)
        payload.update(pricing_digest=digest(canonical(price)), readiness_digest=digest(canonical(ready)))
        self.backend.envelope = {'payload':payload,'signature_base64':base64.b64encode(
            sign(payload, self.private['tim_brydges'], self.temp.name)).decode()}
        self.backend.pricing = price; self.backend.readiness = ready
        self.backend.states = self.states; self.backend.ledger = self.ledger
        self.backend.key_loader = lambda _: self.keys

    def save(self, state):
        row = self.states._serialize_state(state); row['SK'] = {'S':'STATE'}
        self.db.put_item(TableName='security-state', Item=row)

    def hold(self):
        self.backend.reserve(self.state, self.request, dispatch_id=self.dispatch, now=NOW)

    def execute(self):
        return self.backend.execute(self.state, self.request, dispatch_id=self.dispatch,
                                    input_bytes=self.backend.prepared.input_bytes)

    def test_real_authority_allows_exact_once_completion(self):
        self.hold()
        with patch.object(wire.http.client, 'HTTPSConnection',
                return_value=Connection(Response(self.fixture.response))) as network:
            self.execute()
            with self.assertRaises(StateError): self.execute()
        self.assertEqual(network.call_count, 1)
        self.assertEqual(self.fixture.claims.row()['status'], {'S':'COMPLETE'})

    def test_revoked_owner_and_independent_reviewer_block_before_credentials(self):
        self.hold()
        for identity in ('tim_brydges', 'product_spec_reviewer_service'):
            key = self.keys.pop(identity)
            with patch.object(wire.http.client, 'HTTPSConnection') as network:
                with self.assertRaises(StateError): self.execute()
                network.assert_not_called()
            self.keys[identity] = key
        self.fixture.credential.assert_not_called()
        self.assertEqual(self.fixture.claims.row()['status'], {'S':'RESERVED'})

    def test_tampered_allowance_and_missing_prerequisite_block(self):
        self.hold()
        payload = self.backend.envelope['payload']
        old = payload['reserved_micro_usd']; payload['reserved_micro_usd'] = 250001
        with self.assertRaises(StateError): self.execute()
        payload['reserved_micro_usd'] = old
        self.backend.verify_prerequisites.return_value = False
        with self.assertRaises(StateError): self.execute()
        self.fixture.credential.assert_not_called()
        self.assertEqual(self.fixture.claims.row()['status'], {'S':'RESERVED'})

    def test_pause_after_credential_loading_consumes_claim_without_network(self):
        self.hold()
        def pause():
            self.save(replace(self.state, state='PAUSED', version=8))
            return AWS
        self.backend.load_credential = pause
        with patch.object(wire.http.client, 'HTTPSConnection') as network:
            with self.assertRaises(StateError): self.execute()
            network.assert_not_called()
        self.assertEqual(self.fixture.claims.row()['status'], {'S':'STARTED'})

    def test_expired_scope_and_wrong_dispatch_block_send(self):
        self.hold()
        with self.assertRaises(StateError):
            self.backend.execute(self.state, self.request, dispatch_id='0'*64,
                                 input_bytes=self.backend.prepared.input_bytes)
        self.backend.clock = lambda: NOW+timedelta(minutes=11)
        with self.assertRaises(StateError): self.execute()
        self.fixture.credential.assert_not_called()
        self.assertEqual(self.fixture.claims.row()['status'], {'S':'RESERVED'})


if __name__ == '__main__': unittest.main()
