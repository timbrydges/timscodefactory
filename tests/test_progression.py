import base64
import hashlib
import json
import sys
import tempfile
import unittest
from copy import deepcopy
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT)); sys.path.insert(0, str(ROOT/'src'))
from factory_runtime.progression import SignedResultProgressor
from factory_runtime.worker import digest
from factory_state.dispatch import DispatchRequest, DynamoDBDispatchStore
from factory_state.model import CONTROLLER_IDENTITY, Lease, StateError, TaskState
from factory_state.scope import SignedScopeStore, canonical
from scripts.scope_dispatch_canary import fixture_keys, sign

NOW = datetime(2026, 9, 22, 18, tzinfo=timezone.utc)


class MemoryClient:
    def __init__(self): self.items = {}
    @staticmethod
    def key(value): return value['PK']['S'], value['SK']['S']
    def put_item(self, **request): self.items[self.key(request['Item'])] = deepcopy(request['Item'])
    def get_item(self, **request):
        item = self.items.get(self.key(request['Key']))
        return {'Item': deepcopy(item)} if item else {}


class MemoryStates:
    def __init__(self, state): self.state, self.writes = state, []
    def load_state(self, factory_id, task_id):
        return self.state if (factory_id, task_id) == (self.state.factory_id, self.state.task_id) else None
    def persist_transition(self, before, after, **kwargs):
        if before != self.state: raise StateError('stale state')
        self.writes.append((before, after, kwargs)); self.state = after


class SignedResultProgressionTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(); self.addCleanup(self.directory.cleanup)
        self.keys, self.private = fixture_keys(self.directory.name,
            ('tim_brydges', 'independent_inspector_service', 'engineering_agent_service'))
        lease = Lease('lease-1', 'engineering_agent', 'engineering_agent_service', NOW + timedelta(minutes=10))
        self.state = TaskState('factory', 'task-1', 'IMPLEMENTATION', 3, NOW, CONTROLLER_IDENTITY, (lease,))
        self.contract = b'bounded contract'; self.input = b'bounded implementation task'
        self.request = DispatchRequest('lease-1', 'autonomy', 'automatic-progression', 'a'*40,
            digest(self.contract), digest(self.input))
        self.client = MemoryClient(); self.ledger = DynamoDBDispatchStore('state', self.client)
        scope = SignedScopeStore('state', self.client, self.keys)
        times = {'issued_at': int(NOW.timestamp()), 'expires_at': int(NOW.timestamp()) + 300}
        cap = {'kind':'capability','factory_id':'factory','objective_id':'autonomy',
            'capability_id':'automatic-progression','contract_digest':digest(self.contract),
            'owner_identity':'tim_brydges','required_evidence':'signed result','stop_condition':'release ready',**times}
        review = {'kind':'scope_review','factory_id':'factory','task_id':'task-1',
            'binding':self.ledger._binding(self.request),'verdict':'ACCEPTED',
            'reviewer_identity':'independent_inspector_service','rationale':'independent bounded review',**times}
        scope.approve_capability(self.state,self.request,cap,sign(cap,self.private['tim_brydges'],self.directory.name),now=NOW)
        scope.approve_task(self.state,self.request,review,
            sign(review,self.private['independent_inspector_service'],self.directory.name),now=NOW)
        output = b'verified implementation artifact'; dispatch_id = 'd'*64
        payload = {'kind':'role_result','factory_id':'factory','task_id':'task-1',
            'binding':self.ledger._binding(self.request),'dispatch_id':dispatch_id,
            'producer_identity':'engineering_agent_service','output_digest':digest(output),**times}
        receipt = 'sha256:' + hashlib.sha256(canonical(payload)).hexdigest()
        row = {**self.ledger._key(self.state,self.request),'status':{'S':'RECEIPT_RECORDED'},
            'binding':{'S':self.ledger._binding(self.request)},'dispatch_id':{'S':dispatch_id},
            'receipt_digest':{'S':receipt},'result_payload':{'S':canonical(payload).decode()},
            'result_signature':{'S':base64.b64encode(sign(payload,self.private['engineering_agent_service'],self.directory.name)).decode()},
            'result_output':{'S':base64.b64encode(output).decode()}}
        self.client.put_item(TableName='state',Item=row)
        self.states = MemoryStates(self.state)
        self.progressor = SignedResultProgressor(self.states,self.ledger,key_loader=lambda now:self.keys,clock=lambda:NOW)

    def test_signed_result_advances_exactly_one_gate_and_never_releases(self):
        result = self.progressor.advance('factory','task-1',self.request)
        self.assertEqual(result['status'],'ADVANCED'); self.assertEqual(result['state'],'INSPECTION')
        self.assertFalse(result['release_dispatched']); self.assertEqual(len(self.states.writes),1)
        self.assertTrue(self.states.state.leases[0].revoked)
        self.assertIn(result['evidence_id'],self.states.state.consumed_evidence_ids)

    def test_repeat_is_idempotent_and_does_not_write_again(self):
        first = self.progressor.advance('factory','task-1',self.request)
        second = self.progressor.advance('factory','task-1',self.request)
        self.assertEqual(second['status'],'ALREADY_ADVANCED')
        self.assertEqual(second['evidence_id'],first['evidence_id']); self.assertEqual(len(self.states.writes),1)

    def test_tampered_output_signature_and_unrecorded_result_fail_closed(self):
        key = self.client.key(self.ledger._key(self.state,self.request)); original = deepcopy(self.client.items[key])
        for field, value in (
            ('result_output',{'S':base64.b64encode(b'changed').decode()}),
            ('result_signature',{'S':base64.b64encode(b'x'*64).decode()}),
            ('status',{'S':'STARTED'})):
            with self.subTest(field=field):
                self.client.items[key] = {**deepcopy(original),field:value}
                with self.assertRaises(StateError): self.progressor.advance('factory','task-1',self.request)
        self.assertEqual(self.states.writes,[])

    def test_wrong_stage_or_expired_scope_cannot_advance(self):
        self.states.state = TaskState('factory','task-1','QA',3,NOW,CONTROLLER_IDENTITY,self.state.leases)
        with self.assertRaises(StateError): self.progressor.advance('factory','task-1',self.request)
        self.states.state = self.state
        expired = NOW + timedelta(minutes=6)
        self.progressor.clock = lambda: expired
        with self.assertRaises(StateError): self.progressor.advance('factory','task-1',self.request)


if __name__ == '__main__': unittest.main()
