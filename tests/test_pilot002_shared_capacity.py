import copy
import json
from pathlib import Path
import sys
import threading
from concurrent.futures import ThreadPoolExecutor
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
import prepare_pilot002_shared_capacity as p
import test_pilot002_workflow as workflows


class SharedCapacityTests(unittest.TestCase):
    def setUp(self):
        root=Path(__file__).resolve().parents[1]
        self.previous=json.loads((root/'factory/evidence/pilot-002-builder-live-preview.json').read_text())

    def test_only_reservation_differs_from_reviewed_one_call_template(self):
        result=p.render(self.previous['rollback_template'],self.previous)
        self.assertNotIn('ReservedConcurrentExecutions',result['Resources']['BuilderFunction']['Properties'])
        result['Resources']['BuilderFunction']['Properties']['ReservedConcurrentExecutions']=1
        self.assertEqual(result,self.previous['template'])

    def test_drift_extra_changes_and_replacement_rejected(self):
        with self.assertRaises(p.StateError):p.render({},self.previous)
        result=p.render(self.previous['rollback_template'],self.previous)
        changes={'Status':'CREATE_COMPLETE','ExecutionStatus':'AVAILABLE','StackId':self.previous['stack_id'],'Changes':copy.deepcopy(self.previous['changes'])}
        self.assertEqual(p.validate(result,changes,self.previous)['maximum_provider_calls'],1)
        changes['Changes'][0]['ResourceChange']['Replacement']='True'
        with self.assertRaises(p.StateError):p.validate(result,changes,self.previous)
        changes['Changes']=self.previous['changes']*2
        with self.assertRaises(p.StateError):p.validate(result,changes,self.previous)

    def test_racing_workflows_read_one_credential_and_send_once(self):
        fixture=workflows.WorkflowTests();fixture.setUp()
        original=fixture.db.put_item.side_effect;barrier=threading.Barrier(2);lock=threading.Lock()
        def claim(**kwargs):
            self.assertEqual(kwargs['ConditionExpression'],'attribute_not_exists(PK)')
            barrier.wait(timeout=5)
            with lock:return original(**kwargs)
        fixture.db.put_item.side_effect=claim
        def run(_):
            try:return fixture.run_workflow()['status']
            except p.StateError:return 'REJECTED'
        with ThreadPoolExecutor(max_workers=2) as pool:results=list(pool.map(run,range(2)))
        self.assertEqual(sorted(results),['PILOT002_COMPLETED_UNSIGNED','REJECTED'])
        self.assertEqual(fixture.load.call_count,1);self.assertEqual(fixture.adapter.send_once.call_count,1)
        self.assertEqual(len(fixture.rows),1)
        self.assertEqual(next(iter(fixture.rows.values()))['reserved_micro_usd'],{'N':'250000'})


if __name__=='__main__':unittest.main()
