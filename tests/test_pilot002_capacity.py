import copy
import json
from pathlib import Path
import sys
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
import check_pilot002_capacity as p


class CapacityTests(unittest.TestCase):
    def test_observed_ten_slot_account_blocks_one_reservation(self):
        r=p.capacity({'ConcurrentExecutions':10,'UnreservedConcurrentExecutions':10},current_reserved=0,desired_reserved=1,minimum_unreserved=10)
        self.assertEqual(r['status'],'CAPACITY_BLOCKED')
        self.assertEqual(r['minimum_account_limit_under_observed_floor'],11)

    def test_capacity_must_preserve_floor_and_accounts_for_existing_reservation(self):
        for total,unreserved,current in ((11,11,0),(11,10,1)):
            self.assertEqual(p.capacity({'ConcurrentExecutions':total,'UnreservedConcurrentExecutions':unreserved},current_reserved=current,desired_reserved=1,minimum_unreserved=10)['status'],'CAPACITY_READY')

    def test_invalid_capacity_or_expanded_reservation_rejected(self):
        for limit,current,desired in ((True,0,1),(10,0,2),(10,1,1)):
            with self.assertRaises(p.StateError):p.capacity({'ConcurrentExecutions':limit,'UnreservedConcurrentExecutions':10},current_reserved=current,desired_reserved=desired,minimum_unreserved=10)

    def fixture(self):
        root=Path(__file__).resolve().parents[1]
        template=json.loads((root/'factory/evidence/pilot-002-builder-live-preview.json').read_text())['rollback_template']
        functions={};hashes={}
        for role in ('builder','inspector','qa'):
            props=template['Resources'][role.title()+'Function']['Properties'];hashes[role]=role+'-hash'
            functions[role]={k:copy.deepcopy(props[k]) for k in ('Handler','Timeout','Environment','ReservedConcurrentExecutions')}
            functions[role].update(CodeSha256=hashes[role],LastUpdateStatus='Successful')
        return template,functions,hashes

    def test_completed_rollback_is_a_valid_disabled_state(self):
        t,f,h=self.fixture()
        for status in ('UPDATE_COMPLETE','UPDATE_ROLLBACK_COMPLETE'):
            self.assertTrue(p.disabled_snapshot(status,t,t,f,h)['all_roles_disabled'])

    def test_rollback_status_alone_cannot_prove_shutdown(self):
        t,f,h=self.fixture();f['builder']['ReservedConcurrentExecutions']=1
        with self.assertRaises(p.StateError):p.disabled_snapshot('UPDATE_ROLLBACK_COMPLETE',t,t,f,h)
        t,f,h=self.fixture();f['qa']['Environment']['Variables']['FACTORY_PILOT002_EXECUTION_ENABLED']='true'
        with self.assertRaises(p.StateError):p.disabled_snapshot('UPDATE_ROLLBACK_COMPLETE',t,t,f,h)

    def test_in_progress_or_drifted_template_is_not_disabled_proof(self):
        t,f,h=self.fixture()
        with self.assertRaises(p.StateError):p.disabled_snapshot('UPDATE_ROLLBACK_IN_PROGRESS',t,t,f,h)
        changed=copy.deepcopy(t);changed['Description']='drift'
        with self.assertRaises(p.StateError):p.disabled_snapshot('UPDATE_ROLLBACK_COMPLETE',changed,t,f,h)


if __name__=='__main__':unittest.main()
