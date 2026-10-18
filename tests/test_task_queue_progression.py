from dataclasses import replace
import hashlib
import json
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest

from factory_runtime.task_queue import GenericTaskRunner, LocalTaskQueue, QueuedTask
from factory_state.model import StateError


class QueueProgressionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / 'queue.db'
        self.queue = LocalTaskQueue(self.path)
        self.spec = json.loads((Path(__file__).resolve().parents[1] /
            'factory/projects/bonus-library-pagination/task.json').read_text())
        self.raw = json.dumps(self.spec, sort_keys=True).encode()
        self.digest = 'sha256:' + hashlib.sha256(self.raw).hexdigest()
        self.stages = ['IMPLEMENTATION', 'INSPECTION', 'QA']
        self.tasks = [QueuedTask('stage-' + str(i), 'factory', self.spec['task_id'],
            'approval', 'a' * 40, self.digest, state) for i, state in enumerate(self.stages)]
        self.state = 'IMPLEMENTATION'
        self.calls = []
        self.outcome = 'ADVANCED'

    def admit(self, **kwargs):
        args = dict(repository=self.spec['repository'], target_commit=self.spec['target_commit'],
                    contract_bytes=self.raw, tasks=self.tasks)
        args.update(kwargs)
        self.queue.enqueue_plan('pagination-plan', **args)

    def scheduler(self, task):
        def tick(*args, expected_state=None):
            if self.state != expected_state:
                raise StateError('authoritative state differs from queued stage')
            self.calls.append(self.state)
            if self.outcome == 'CRASH':
                raise TimeoutError('uncertain external outcome')
            if self.outcome == 'ADVANCED':
                self.state = {'IMPLEMENTATION': 'INSPECTION', 'INSPECTION': 'QA', 'QA': 'SECURITY'}[self.state]
            return {'status': self.outcome, 'worker_invocations': 1, 'release_dispatched': False}
        return SimpleNamespace(activation=task, tick=tick,
            states=SimpleNamespace(load_state=lambda *args: SimpleNamespace(state=self.state)))

    def runner(self):
        return GenericTaskRunner(self.queue, self.scheduler, enabled=True)

    def test_progression_survives_restart_and_stops_before_security(self):
        self.admit(); self.queue.pause(False)
        for stage in self.stages:
            self.assertEqual(self.state, stage)
            self.assertEqual(self.runner().tick()['status'], 'TICK_COMPLETED')
            self.queue = LocalTaskQueue(self.path)
            self.admit()  # Must not reset already consumed stages.
        self.assertEqual(self.state, 'SECURITY')
        self.assertEqual(self.calls, self.stages)
        self.assertEqual(self.runner().tick()['status'], 'IDLE_OR_PAUSED')

    def test_rejection_blocks_all_successors(self):
        self.admit(); self.queue.pause(False); self.outcome = 'REJECTED'
        self.assertEqual(self.runner().tick()['status'], 'REJECTED')
        self.assertEqual(self.runner().tick()['status'], 'IDLE_OR_PAUSED')
        self.assertEqual(self.queue.inspect('stage-1')['status'], 'PENDING')
        self.assertEqual(len(self.calls), 1)

    def test_uncertainty_blocks_successors_after_restart(self):
        self.admit(); self.queue.pause(False); self.outcome = 'CRASH'
        self.assertEqual(self.runner().tick()['status'], 'NEEDS_RECONCILIATION')
        self.queue = LocalTaskQueue(self.path); self.admit()
        self.assertEqual(self.runner().tick()['status'], 'IDLE_OR_PAUSED')
        self.assertEqual(len(self.calls), 1)

    def test_pause_between_stages_keeps_progress(self):
        self.admit(); self.queue.pause(False); self.runner().tick()
        self.queue.pause()
        self.assertEqual(self.runner().tick()['status'], 'IDLE_OR_PAUSED')
        self.queue.pause(False); self.runner().tick()
        self.assertEqual(self.calls, ['IMPLEMENTATION', 'INSPECTION'])

    def test_pins_and_stage_sequence_cannot_drift(self):
        for change in [dict(target_commit='b' * 40), dict(repository='someone/else'),
                       dict(contract_bytes=self.raw + b' '), dict(tasks=list(reversed(self.tasks))),
                       dict(tasks=[replace(t, source_commit='b' * 40) if i else t for i,t in enumerate(self.tasks)])]:
            with self.subTest(change=change), self.assertRaises(StateError):
                self.admit(**change)
        self.assertIsNone(self.queue.inspect('stage-0'))

    def test_plan_id_is_immutable(self):
        self.admit()
        changed = [replace(t, activation_id='replacement') for t in self.tasks]
        with self.assertRaises(StateError): self.admit(tasks=changed)

    def test_wrong_authoritative_stage_never_dispatches(self):
        self.admit(); self.queue.pause(False); self.state = 'QA'
        self.assertEqual(self.runner().tick()['status'], 'NEEDS_RECONCILIATION')
        self.assertEqual(self.calls, [])

    def test_release_ready_does_not_unlock_next_stage(self):
        self.admit(); self.queue.pause(False); self.outcome = 'RELEASE_READY'
        self.runner().tick()
        self.assertIsNone(self.queue.claim())

    def test_enqueue_conflict_rolls_back_whole_plan(self):
        self.queue.enqueue(self.tasks[1])
        import sqlite3
        with self.assertRaises(sqlite3.IntegrityError): self.admit()
        self.assertIsNone(self.queue.inspect('stage-0'))


if __name__ == '__main__':
    unittest.main()
