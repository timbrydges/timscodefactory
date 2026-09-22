import sys
import tempfile
import unittest
from copy import deepcopy
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT)); sys.path.insert(0, str(ROOT/'src'))
from factory_runtime.intake import AuthenticatedIntakeService
from factory_runtime.worker import digest
from factory_state.dispatch import DynamoDBDispatchStore
from factory_state.model import CONTROLLER_IDENTITY, StateError, TaskState
from scripts.scope_dispatch_canary import fixture_keys, sign

NOW = datetime(2026,9,22,19,tzinfo=timezone.utc)


class ConditionalFailure(Exception):
    response = {'Error': {'Code': 'ConditionalCheckFailedException'}}


class MemoryClient:
    def __init__(self): self.items = {}
    @staticmethod
    def key(value): return value['PK']['S'], value['SK']['S']
    def put_item(self, **request):
        key = self.key(request['Item'])
        if key in self.items: raise ConditionalFailure()
        self.items[key] = deepcopy(request['Item'])
    def get_item(self, **request):
        item = self.items.get(self.key(request['Key']))
        return {'Item':deepcopy(item)} if item else {}


class MemoryStates:
    def __init__(self,state): self.state,self.writes=state,0
    def load_state(self,factory_id,task_id):
        return self.state if (factory_id,task_id)==(self.state.factory_id,self.state.task_id) else None
    def persist_transition(self,before,after,**kwargs):
        if before != self.state: raise StateError('stale state')
        self.state=after;self.writes+=1


class MemoryLedger:
    _binding=staticmethod(DynamoDBDispatchStore._binding)
    _key=staticmethod(DynamoDBDispatchStore._key)
    def __init__(self,client): self.client=client;self.table_name='state';self.rows={};self.enqueues=0
    def read(self,state,request):
        row=self.rows.get(request.lease_id)
        if row and row['binding'] != {'S':self._binding(request)}: raise StateError('binding conflict')
        return deepcopy(row)
    def enqueue(self,state,request,**kwargs):
        dispatch='dispatch-'+request.lease_id
        self.rows[request.lease_id]={**self._key(state,request),'binding':{'S':self._binding(request)},
            'status':{'S':'READY'},'dispatch_id':{'S':dispatch}}
        self.enqueues+=1
        return dispatch


class AuthenticatedIntakeTests(unittest.TestCase):
    def setUp(self):
        self.directory=tempfile.TemporaryDirectory();self.addCleanup(self.directory.cleanup)
        self.keys,self.private=fixture_keys(self.directory.name,
            ('tim_brydges','independent_inspector_service','engineering_agent_service'))
        self.states=MemoryStates(TaskState('factory','task-1','IMPLEMENTATION',4,NOW,CONTROLLER_IDENTITY))
        self.client=MemoryClient();self.ledger=MemoryLedger(self.client)
        self.service=AuthenticatedIntakeService(self.states,self.ledger,key_loader=lambda at:self.keys,clock=lambda:NOW)

    def plan(self):
        return self.service.prepare('factory','task-1',role_id='engineering_agent',source_commit='a'*40,
            objective_id='factory-autonomy',capability_id='authenticated-intake',
            contract_bytes=b'approved Factory contract',input_bytes=b'exact implementation request',
            reviewer_identity='independent_inspector_service',required_evidence='signed implementation result',
            stop_condition='stop after one queued role result',rationale='independent scope review')

    def signatures(self,plan):
        return {'owner_signature':sign(plan.capability_payload,self.private['tim_brydges'],self.directory.name),
            'reviewer_signature':sign(plan.review_payload,self.private['independent_inspector_service'],self.directory.name)}

    def test_signed_plan_issues_one_lease_and_queues_exact_request(self):
        plan=self.plan();result=self.service.activate(plan,**self.signatures(plan))
        self.assertEqual(result['status'],'QUEUED');self.assertEqual(result['model_calls'],0)
        self.assertFalse(result['release_dispatched']);self.assertEqual(self.states.writes,1)
        self.assertEqual(self.ledger.enqueues,1);self.assertEqual(self.states.state.leases[-1],plan.lease)
        self.assertEqual(self.ledger.rows[plan.lease.lease_id]['status'],{'S':'READY'})

    def test_restart_reuses_lease_scope_and_queue_without_duplicate_writes(self):
        plan=self.plan();signatures=self.signatures(plan)
        first=self.service.activate(plan,**signatures);second=self.service.activate(plan,**signatures)
        self.assertEqual(first['dispatch_id'],second['dispatch_id']);self.assertEqual(second['status'],'ALREADY_QUEUED')
        self.assertEqual(self.states.writes,1);self.assertEqual(self.ledger.enqueues,1)

    def test_bad_signatures_fail_before_lease_or_queue(self):
        plan=self.plan()
        with self.assertRaises(StateError):
            self.service.activate(plan,owner_signature=b'x'*64,
                reviewer_signature=self.signatures(plan)['reviewer_signature'])
        self.assertEqual(self.states.writes,0);self.assertEqual(self.states.state.leases,())
        self.assertEqual(self.ledger.enqueues,0)

    def test_existing_scope_cannot_be_rewritten_during_restart(self):
        plan=self.plan();self.service.activate(plan,**self.signatures(plan))
        plan.capability_payload['required_evidence']='different evidence'
        signatures=self.signatures(plan)
        with self.assertRaisesRegex(StateError,'conflicts with immutable approval'):
            self.service.activate(plan,**signatures)
        self.assertEqual(self.states.writes,1);self.assertEqual(self.ledger.enqueues,1)

    def test_wrong_role_existing_work_and_release_stage_fail_closed(self):
        with self.assertRaises(StateError):
            self.service.prepare('factory','task-1',role_id='software_architect',source_commit='a'*40,
                objective_id='x',capability_id='y',contract_bytes=b'c',input_bytes=b'i',
                reviewer_identity='independent_inspector_service',required_evidence='e',stop_condition='s',rationale='r')
        self.states.state=TaskState('factory','task-1','RELEASE_READY',5,NOW,CONTROLLER_IDENTITY)
        with self.assertRaises(StateError): self.plan()

    def test_fabricated_plan_cannot_bypass_stage_locked_role(self):
        plan=self.plan()
        from dataclasses import replace
        forged=replace(plan,lease=replace(plan.lease,role_id='software_architect',
            authoritative_identity='software_architect_service'))
        with self.assertRaisesRegex(StateError,'invalid stage or role binding'):
            self.service.activate(forged,**self.signatures(plan))
        self.assertEqual(self.states.writes,0);self.assertEqual(self.ledger.enqueues,0)


if __name__=='__main__': unittest.main()
