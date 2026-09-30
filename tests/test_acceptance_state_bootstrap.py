import sys
import unittest
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / 'scripts'), str(ROOT / 'src')]

from factory_state.model import OWNER_IDENTITY, TaskState
from initialize_acceptance_task_state import (
    FACTORY, TASK, _matches,
)


class AcceptanceStateBootstrapTests(unittest.TestCase):
    def test_exact_bootstrap_state_matches(self):
        state = TaskState(
            FACTORY, TASK, 'IMPLEMENTATION', 1,
            datetime(2026, 9, 30, tzinfo=timezone.utc), OWNER_IDENTITY)
        self.assertTrue(_matches(state))

    def test_any_existing_drift_fails_match(self):
        base = dict(
            factory_id=FACTORY, task_id=TASK, state='IMPLEMENTATION', version=1,
            updated_at=datetime(2026, 9, 30, tzinfo=timezone.utc),
            updated_by=OWNER_IDENTITY)
        for change in (
            {'state': 'INTAKE'},
            {'version': 2},
            {'updated_by': 'factory_controller_service'},
            {'task_id': 'other-task'},
        ):
            with self.subTest(change=change):
                self.assertFalse(_matches(TaskState(**{**base, **change})))
        self.assertFalse(_matches(None))


if __name__ == '__main__':
    unittest.main()
