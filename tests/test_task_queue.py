import json
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest

from factory_runtime.autonomy import AutonomyActivation, AutonomousScheduler
from factory_runtime.task_queue import GenericTaskRunner, LocalTaskQueue, QueuedTask
from factory_state.model import StateError


class TaskQueueTests(unittest.TestCase):
    def setUp(self):
        self.tmp = TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / 'queue.db'
        self.queue = LocalTaskQueue(self.path)
        self.task = QueuedTask('entry-one', 'factory', 'pagination', 'approval-one',
                               'a' * 40, 'sha256:' + 'b' * 64)
        self.calls = []

    def scheduler(self, task):
        def tick(factory, task_id):
            self.calls.append(task_id)
            return {'status': 'ADVANCED', 'worker_invocations': 1, 'release_dispatched': False}
        return SimpleNamespace(activation=task, tick=tick)

    def ready(self):
        self.queue.enqueue(self.task)
        self.queue.pause(False)
        return GenericTaskRunner(self.queue, self.scheduler, enabled=True)

    def test_default_runner_and_queue_are_disabled(self):
        self.queue.enqueue(self.task)
        self.assertEqual(GenericTaskRunner(self.queue, self.scheduler).tick()['status'], 'DISABLED')
        self.assertEqual(GenericTaskRunner(self.queue, self.scheduler, enabled=True).tick()['status'], 'IDLE_OR_PAUSED')
        self.assertEqual(self.calls, [])
        self.assertEqual(self.queue.inspect(self.task.entry_id)['status'], 'PENDING')

    def test_two_task_contracts_use_same_runner(self):
        runner = self.ready()
        self.queue.enqueue(replace(self.task, entry_id='entry-two', task_id='other-feature',
                                   activation_id='approval-two', contract_digest='sha256:' + 'c' * 64))
        self.assertEqual(runner.tick()['status'], 'TICK_COMPLETED')
        self.assertEqual(runner.tick()['status'], 'TICK_COMPLETED')
        self.assertEqual(self.calls, ['pagination', 'other-feature'])
        self.assertEqual(runner.tick()['status'], 'IDLE_OR_PAUSED')

    def test_two_connections_cannot_claim_same_entry(self):
        self.ready()
        other = LocalTaskQueue(self.path)
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(lambda q: q.claim(), [self.queue, other]))
        self.assertEqual(sum(r is not None for r in results), 1)

    def test_crash_after_claim_stays_started_after_reopen(self):
        self.ready()
        self.assertEqual(self.queue.claim(), self.task)
        reopened = LocalTaskQueue(self.path)
        reopened.enqueue(self.task)
        self.assertIsNone(reopened.claim())
        self.assertEqual(reopened.inspect(self.task.entry_id)['status'], 'STARTED')

    def test_uncertain_call_is_not_retried_and_error_text_not_saved(self):
        runner = self.ready()
        def failing(task):
            def tick(*args):
                self.calls.append(task.task_id)
                raise TimeoutError('sensitive provider response')
            return SimpleNamespace(activation=task, tick=tick)
        runner.scheduler_for = failing
        self.assertEqual(runner.tick()['status'], 'NEEDS_RECONCILIATION')
        self.queue.enqueue(self.task)
        self.assertEqual(runner.tick()['status'], 'IDLE_OR_PAUSED')
        self.assertEqual(self.calls, ['pagination'])
        self.assertNotIn('sensitive', json.dumps(self.queue.inspect(self.task.entry_id)))

    def test_pause_persists_and_resume_does_not_reset_consumed(self):
        runner = self.ready()
        self.queue.pause()
        self.assertIsNone(LocalTaskQueue(self.path).claim())
        self.queue.pause(False)
        runner.tick()
        self.queue.pause(); self.queue.pause(False)
        self.assertEqual(runner.tick()['status'], 'IDLE_OR_PAUSED')
        self.assertEqual(len(self.calls), 1)

    def test_changed_entry_and_unpinned_task_rejected(self):
        self.ready()
        with self.assertRaises(StateError):
            self.queue.enqueue(replace(self.task, task_id='changed'))
        with self.assertRaises(StateError):
            self.queue.enqueue(replace(self.task, source_commit='main'))

    def test_activation_mismatch_blocks_scheduler_call(self):
        runner = self.ready()
        runner.scheduler_for = lambda task: self.scheduler(replace(task, contract_digest='sha256:' + 'e' * 64))
        self.assertEqual(runner.tick()['status'], 'NEEDS_RECONCILIATION')
        self.assertEqual(self.calls, [])

    def test_rejected_and_invalid_outcomes_are_not_success(self):
        for state, count, release, expected in [('REJECTED', 1, False, 'REJECTED'),
                ('UNKNOWN', 0, False, 'NEEDS_RECONCILIATION'),
                ('ADVANCED', 2, False, 'NEEDS_RECONCILIATION'),
                ('ADVANCED', 1, True, 'NEEDS_RECONCILIATION')]:
            with self.subTest(state=state, count=count, release=release):
                task = replace(self.task, entry_id=f'entry-{state}-{count}-{release}')
                self.queue.enqueue(task); self.queue.pause(False)
                resolver = lambda t: SimpleNamespace(activation=t, tick=lambda *args: {
                    'status': state, 'worker_invocations': count, 'release_dispatched': release})
                self.assertEqual(GenericTaskRunner(self.queue, resolver, enabled=True).tick()['status'], expected)

    def test_existing_scheduler_stops_paused_authoritative_task(self):
        runner = self.ready()
        now = datetime.now(timezone.utc)
        activation = AutonomyActivation(self.task.activation_id, self.task.factory_id,
            self.task.task_id, self.task.source_commit, self.task.contract_digest,
            now - timedelta(minutes=1), now + timedelta(minutes=5))
        states = SimpleNamespace(load_state=lambda *args: SimpleNamespace(state='PAUSED'))
        scheduler = AutonomousScheduler(None, states, None, activation, clock=lambda: now, enabled=True)
        runner.scheduler_for = lambda task: scheduler
        self.assertEqual(runner.tick()['status'], 'STOPPED')
        self.assertEqual(self.calls, [])

    def test_expired_existing_scheduler_activation_blocks_work(self):
        runner = self.ready()
        now = datetime.now(timezone.utc)
        activation = AutonomyActivation(self.task.activation_id, self.task.factory_id,
            self.task.task_id, self.task.source_commit, self.task.contract_digest,
            now - timedelta(minutes=5), now - timedelta(minutes=1))
        runner.scheduler_for = lambda task: AutonomousScheduler(None, None, None, activation,
                                                                clock=lambda: now, enabled=True)
        self.assertEqual(runner.tick()['status'], 'NEEDS_RECONCILIATION')

    def test_acceptance_task_grants_no_execution_authority(self):
        path = Path(__file__).resolve().parents[1] / 'factory/projects/bonus-library-pagination/task.json'
        task = json.loads(path.read_text())
        self.assertEqual(task['repository'], 'timbrydges/bonus-library')
        for field in ('execution_authorized', 'spending_authorized', 'signing_authorized', 'release_authorized'):
            self.assertIs(task[field], False)


if __name__ == '__main__':
    unittest.main()
