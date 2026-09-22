import sys
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'src'))
from factory_runtime.autonomy import AutonomousCycle
from factory_runtime.intake import IntakePlan
from factory_runtime.receipt_transport import ReceiptVersions, SignedReceiptBundle
from factory_runtime.worker import digest
from factory_state.dispatch import DispatchRequest, DynamoDBDispatchStore
from factory_state.model import Lease, StateError, TaskState, CONTROLLER_IDENTITY

NOW=datetime(2026,9,22,20,tzinfo=timezone.utc)
CONTRACT=b'contract';INPUT=b'input'


def make_plan():
    lease=Lease('auto-'+'2'*24,'engineering_agent','engineering_agent_service',NOW+timedelta(minutes=15))
    request=DispatchRequest(lease.lease_id,'autonomy','cycle','a'*40,digest(CONTRACT),digest(INPUT))
    return IntakePlan('factory','task-1','IMPLEMENTATION',1,lease,request,{}, {})


class States:
    def __init__(self):self.state=TaskState('factory','task-1','IMPLEMENTATION',1,NOW,CONTROLLER_IDENTITY)
    def load_state(self,*args):return self.state


class Ledger:
    _binding=staticmethod(DynamoDBDispatchStore._binding)
    def __init__(self):self.row=None
    def read(self,*args):return self.row


class Intake:
    def __init__(self):self.states=States();self.ledger=Ledger();self.calls=0
    def activate(self,plan,**signatures):
        self.calls+=1;self.ledger.row={'status':{'S':'READY'},'dispatch_id':{'S':'dispatch'}}
        return {'status':'QUEUED','dispatch_id':'dispatch'}


class Receipts:
    def __init__(self):self.calls=0
    def load(self,*args):self.calls+=1;return SignedReceiptBundle('sha256:'+'f'*64,b'o'*64,b'r'*64)


class Worker:
    def __init__(self,ledger):self.ledger=ledger;self.calls=0
    def run(self,*args,**kwargs):
        self.calls+=1
        if self.ledger.row['status']=={'S':'STARTED'}:return {'status':'NEEDS_RECONCILIATION'}
        self.ledger.row['status']={'S':'RECEIPT_RECORDED'}
        return {'status':'RECEIPT_RECORDED','receipt_digest':'sha256:'+'e'*64}


class Progressor:
    def __init__(self):self.calls=0
    def advance(self,*args):
        self.calls+=1
        return {'status':'ADVANCED' if self.calls==1 else 'ALREADY_ADVANCED','state':'INSPECTION'}


class AutonomousCycleTests(unittest.TestCase):
    def setUp(self):
        self.plan=make_plan();self.intake=Intake();self.receipts=Receipts()
        self.worker=Worker(self.intake.ledger);self.progressor=Progressor()

    def cycle(self,enabled=True):
        return AutonomousCycle(self.intake,self.worker,self.progressor,self.receipts,enabled=enabled)

    def test_disabled_by_default(self):
        with self.assertRaisesRegex(StateError,'disabled'):
            self.cycle(False).step(self.plan,ReceiptVersions('o','r'),input_bytes=INPUT,contract_bytes=CONTRACT)

    def test_one_step_composes_receipts_intake_worker_and_progression(self):
        result=self.cycle().step(self.plan,ReceiptVersions('o','r'),input_bytes=INPUT,contract_bytes=CONTRACT)
        self.assertEqual(result['status'],'ADVANCED');self.assertEqual(result['worker_invocations'],1)
        self.assertFalse(result['release_dispatched']);self.assertEqual(self.receipts.calls,1)
        self.assertEqual(self.intake.calls,self.worker.calls,self.progressor.calls)

    def test_restart_after_receipt_skips_transport_intake_and_worker(self):
        cycle=self.cycle();cycle.step(self.plan,ReceiptVersions('o','r'),input_bytes=INPUT,contract_bytes=CONTRACT)
        result=cycle.step(self.plan,ReceiptVersions('o','r'),input_bytes=INPUT,contract_bytes=CONTRACT)
        self.assertEqual(result['status'],'ALREADY_ADVANCED');self.assertEqual(result['worker_invocations'],0)
        self.assertEqual(self.receipts.calls,1);self.assertEqual(self.intake.calls,1);self.assertEqual(self.worker.calls,1)

    def test_started_unknown_outcome_never_reinvokes_external_role(self):
        self.intake.ledger.row={'status':{'S':'STARTED'},'dispatch_id':{'S':'dispatch'}}
        result=self.cycle().step(self.plan,ReceiptVersions('o','r'),input_bytes=INPUT,contract_bytes=CONTRACT)
        self.assertEqual(result['status'],'NEEDS_RECONCILIATION');self.assertEqual(result['worker_invocations'],0)
        self.assertEqual(self.receipts.calls,0);self.assertEqual(self.intake.calls,0)


if __name__=='__main__':unittest.main()
