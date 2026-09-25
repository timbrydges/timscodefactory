import sys
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))

from factory_runtime.autonomy import (AutonomousScheduler, AutonomyActivation,
                                      ScheduledAutonomyJob)
from factory_runtime.intake import IntakePlan
from factory_runtime.receipt_transport import ReceiptVersions
from factory_runtime.worker import digest
from factory_state.dispatch import DispatchRequest
from factory_state.model import CONTROLLER_IDENTITY, Lease, StateError, TaskState

NOW = datetime(2026, 9, 22, 22, tzinfo=timezone.utc)
CONTRACT = b'approved contract'
INPUT = b'approved input'
COMMIT = 'a' * 40


def task_state(state='IMPLEMENTATION', version=3):
    return TaskState('factory', 'task-1', state, version, NOW, CONTROLLER_IDENTITY)


def job(state='IMPLEMENTATION', version=3, source_commit=COMMIT,
        contract_digest=None):
    contract_digest = contract_digest or digest(CONTRACT)
    lease = Lease('auto-' + '2' * 24, 'engineering_agent',
                  'engineering_agent_service', NOW + timedelta(minutes=15))
    request = DispatchRequest(lease.lease_id, 'autonomy', 'scheduler', source_commit,
                              contract_digest, digest(INPUT))
    plan = IntakePlan('factory', 'task-1', state, version, lease, request, {}, {})
    return ScheduledAutonomyJob(plan, ReceiptVersions('owner-v1', 'review-v1'),
                                INPUT, CONTRACT)


class States:
    def __init__(self, state=None):
        self.state = state or task_state()

    def load_state(self, *_):
        return self.state


class Jobs:
    def __init__(self, value=None):
        self.value = value or job()
        self.calls = 0

    def load(self, *_):
        self.calls += 1
        return self.value


class Cycle:
    def __init__(self, result=None):
        self.result = result or {'status': 'ADVANCED', 'worker_invocations': 1,
                                 'release_dispatched': False}
        self.calls = 0

    def step(self, *_args, **_kwargs):
        self.calls += 1
        return dict(self.result)


class AutonomousSchedulerTests(unittest.TestCase):
    def activation(self, **changes):
        values = {'activation_id': 'factory-autonomy-001', 'factory_id': 'factory',
                  'task_id': 'task-1', 'source_commit': COMMIT,
                  'contract_digest': digest(CONTRACT),
                  'starts_at': NOW - timedelta(minutes=1),
                  'expires_at': NOW + timedelta(hours=1)}
        values.update(changes)
        return AutonomyActivation(**values)

    def scheduler(self, *, state=None, source=None, cycle=None, activation=None,
                  enabled=True, clock=lambda: NOW):
        states = States(state)
        jobs = source or Jobs()
        runner = cycle or Cycle()
        value = AutonomousScheduler(runner, states, jobs,
            activation or self.activation(), clock=clock, enabled=enabled)
        return value, jobs, runner

    def test_disabled_by_default(self):
        scheduler, _, _ = self.scheduler(enabled=False)
        with self.assertRaisesRegex(StateError, 'disabled'):
            scheduler.tick('factory', 'task-1')

    def test_one_tick_runs_at_most_one_non_release_cycle(self):
        scheduler, jobs, cycle = self.scheduler()
        result = scheduler.tick('factory', 'task-1')
        self.assertEqual(result['status'], 'ADVANCED')
        self.assertEqual(result['worker_invocations'], 1)
        self.assertFalse(result['release_dispatched'])
        self.assertEqual(result['activation_id'], 'factory-autonomy-001')
        self.assertEqual(jobs.calls, cycle.calls, 1)

    def test_pause_and_release_ready_stop_before_loading_job(self):
        for state, expected in (('PAUSED', 'STOPPED'),
                                ('RELEASE_READY', 'RELEASE_READY')):
            with self.subTest(state=state):
                scheduler, jobs, cycle = self.scheduler(state=task_state(state))
                result = scheduler.tick('factory', 'task-1')
                self.assertEqual(result['status'], expected)
                self.assertEqual(result['worker_invocations'], 0)
                self.assertEqual(jobs.calls, cycle.calls, 0)

    def test_expired_or_wrong_target_activation_fails_closed(self):
        expired = self.activation(expires_at=NOW)
        scheduler, _, _ = self.scheduler(activation=expired)
        with self.assertRaisesRegex(StateError, 'outside'):
            scheduler.tick('factory', 'task-1')
        scheduler, _, _ = self.scheduler()
        with self.assertRaisesRegex(StateError, 'target'):
            scheduler.tick('factory', 'other')

    def test_activation_over_24_hours_fails_before_loading_job(self):
        scheduler, jobs, cycle = self.scheduler(
            activation=self.activation(expires_at=NOW + timedelta(hours=24)))
        with self.assertRaisesRegex(StateError, 'activation window'):
            scheduler.tick('factory', 'task-1')
        self.assertEqual(jobs.calls, 0)
        self.assertEqual(cycle.calls, 0)

    def test_malformed_activation_binding_fails_before_state_read(self):
        scheduler, _, _ = self.scheduler(
            activation=self.activation(source_commit='main'))
        with self.assertRaisesRegex(StateError, 'binding'):
            scheduler.tick('factory', 'task-1')

    def test_changed_source_contract_or_state_binding_is_rejected(self):
        cases = (job(source_commit='b' * 40),
                 job(contract_digest='sha256:' + 'c' * 64),
                 job(version=4))
        for changed in cases:
            with self.subTest(request=changed.plan.request):
                scheduler, _, cycle = self.scheduler(source=Jobs(changed))
                with self.assertRaisesRegex(StateError, 'differs'):
                    scheduler.tick('factory', 'task-1')
                self.assertEqual(cycle.calls, 0)

    def test_cycle_cannot_widen_to_multiple_calls_or_release(self):
        for result in ({'status': 'ADVANCED', 'worker_invocations': 2,
                        'release_dispatched': False},
                       {'status': 'ADVANCED', 'worker_invocations': 1,
                        'release_dispatched': True}):
            with self.subTest(result=result):
                scheduler, _, _ = self.scheduler(cycle=Cycle(result))
                with self.assertRaisesRegex(StateError, 'authority'):
                    scheduler.tick('factory', 'task-1')


if __name__ == '__main__':
    unittest.main()
