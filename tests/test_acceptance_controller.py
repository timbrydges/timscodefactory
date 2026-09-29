import shutil
import tempfile
import unittest
from datetime import datetime, timedelta
from pathlib import Path

import yaml

from factory_runtime.acceptance_controller import AcceptanceController
from factory_runtime.autonomy import AutonomyActivation, AutonomousScheduler
from factory_state.model import CONTROLLER_IDENTITY, StateError, TaskState

ROOT = Path(__file__).resolve().parents[1]
CONTRACT = yaml.safe_load((ROOT / 'factory/autonomy/operating-contract.yaml').read_text())
NOW = datetime.fromisoformat(CONTRACT['pricing_reference']['observed_at'].replace('Z', '+00:00')) + timedelta(hours=1)
COMMIT = 'a' * 40
EVENT = {'factory_id': 'tims-software-factory',
         'task_id': 'deterministic-text-fingerprint', 'mode': 'acceptance'}


class States:
    reads = 0

    def load_state(self, factory_id, task_id):
        self.reads += 1
        return TaskState(factory_id, task_id, 'RELEASE_READY', 1, NOW, CONTROLLER_IDENTITY)


class NoWork:
    def __getattr__(self, name):
        raise AssertionError('acceptance controller reached a job or worker')


class AcceptanceControllerTests(unittest.TestCase):
    def root(self, *, active=False, clear_gates=False):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        root = Path(directory.name)
        shutil.copytree(ROOT / 'factory', root / 'factory')
        shutil.copytree(ROOT / 'docs', root / 'docs')
        if active or clear_gates:
            path = root / 'factory/autonomy/operating-contract.yaml'
            contract = yaml.safe_load(path.read_text())
            if active:
                contract['status'] = 'ACTIVE'
            if clear_gates:
                contract['activation']['pending_gates'] = []
            path.write_text(yaml.safe_dump(contract, sort_keys=False))
        if active:
            for name, parent in (('provider-live-activation.yaml', 'approved_live_targets'),
                                 ('provider-models.yaml', 'targets')):
                path = root / 'factory/profiles' / name
                document = yaml.safe_load(path.read_text())
                document[parent]['coding_primary_sol_live']['enabled'] = True
                path.write_text(yaml.safe_dump(document, sort_keys=False))
        return root

    def controller(self, root, *, enabled=True, now=NOW, source=COMMIT):
        activation = AutonomyActivation('acceptance-1', EVENT['factory_id'], EVENT['task_id'],
            source, 'sha256:' + CONTRACT['acceptance_target']['contract_sha256'],
            NOW - timedelta(minutes=1), NOW + timedelta(hours=1))
        states = States()
        clock = lambda: now
        scheduler = AutonomousScheduler(NoWork(), states, NoWork(), activation,
            clock=clock, enabled=True)
        return AcceptanceController(root, activation, scheduler,
            deployed_commit=COMMIT, clock=clock, enabled=enabled), states

    def test_default_and_checked_in_contract_deny_before_state_read(self):
        controller, states = self.controller(ROOT, enabled=False)
        with self.assertRaisesRegex(StateError, 'disabled'):
            controller.tick(EVENT)
        controller, _ = self.controller(ROOT)
        with self.assertRaisesRegex(StateError, 'active deployment'):
            controller.tick(EVENT)
        self.assertEqual(states.reads, 0)

    def test_clearing_gates_without_active_status_still_denies(self):
        controller, states = self.controller(self.root(clear_gates=True))
        with self.assertRaisesRegex(StateError, 'active deployment'):
            controller.tick(EVENT)
        self.assertEqual(states.reads, 0)

    def test_exact_active_stop_does_not_load_job_or_dispatch_release(self):
        controller, states = self.controller(self.root(active=True, clear_gates=True))
        result = controller.tick(EVENT)
        self.assertEqual(result['status'], 'RELEASE_READY')
        self.assertEqual(result['worker_invocations'], 0)
        self.assertFalse(result['release_dispatched'])
        self.assertEqual(states.reads, 1)

    def test_active_contract_with_disabled_target_still_denies(self):
        root = self.root(active=True, clear_gates=True)
        path = root / 'factory/profiles/provider-models.yaml'
        catalog = yaml.safe_load(path.read_text())
        catalog['targets']['coding_primary_sol_live']['enabled'] = False
        path.write_text(yaml.safe_dump(catalog, sort_keys=False))
        controller, states = self.controller(root)
        with self.assertRaisesRegex(StateError, 'target switches'):
            controller.tick(EVENT)
        self.assertEqual(states.reads, 0)

    def test_wrong_event_source_and_stale_quote_fail_before_state_read(self):
        root = self.root(active=True, clear_gates=True)
        controller, states = self.controller(root)
        for event in ({**EVENT, 'task_id': 'other'}, {**EVENT, 'extra': True}):
            with self.assertRaisesRegex(StateError, 'exact task'):
                controller.tick(event)
        wrong, _ = self.controller(root, source='b' * 40)
        with self.assertRaisesRegex(StateError, 'active deployment'):
            wrong.tick(EVENT)
        stale, _ = self.controller(root, now=NOW + timedelta(days=2))
        with self.assertRaises(StateError):
            stale.tick(EVENT)
        self.assertEqual(states.reads, 0)


if __name__ == '__main__':
    unittest.main()
