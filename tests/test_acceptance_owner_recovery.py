import sys
import unittest
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / 'src'), str(ROOT / 'scripts')]
from factory_state.model import Lease, TaskState, StateError
from recover_acceptance_missing_artifact import prepare, FACTORY, TASK, EVIDENCE, LEASE_IDS


class OwnerRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.now = datetime.now(timezone.utc)
        self.before = TaskState(FACTORY, TASK, 'INSPECTION', 6, self.now,
            'factory_controller_service', leases=tuple(Lease(x, 'engineering_agent',
                'engineering_agent_service', self.now + timedelta(hours=1), True)
                for x in sorted(LEASE_IDS)), consumed_evidence_ids=frozenset((EVIDENCE,)))

    def test_preserves_all_history_and_emits_owner_audit(self):
        after, audit = prepare(self.before, self.now)
        self.assertEqual((after.state, after.version), ('IMPLEMENTATION', 7))
        self.assertEqual(after.leases, self.before.leases)
        self.assertEqual(after.consumed_evidence_ids, self.before.consumed_evidence_ids)
        self.assertEqual(audit['event_type'], 'OWNER_OVERRIDE')
        self.assertEqual(after.updated_by, 'tim_brydges')
        with self.assertRaises(StateError):
            prepare(after, self.now)

    def test_rejects_drift_or_active_lease_without_mutation(self):
        for changes in ({'state': 'IMPLEMENTATION'}, {'version': 7},
                {'task_id': 'other'}, {'consumed_evidence_ids': frozenset()},
                {'leases': self.before.leases[:3]},
                {'leases': (replace(self.before.leases[0], revoked=False),) + self.before.leases[1:]}):
            with self.subTest(changes=changes), self.assertRaises(StateError):
                prepare(replace(self.before, **changes), self.now)
