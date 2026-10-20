import asyncio
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
import hashlib
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase
from unittest.mock import AsyncMock, Mock

from factory_runtime.development_schedule import DevelopmentSchedule, scheduled_tick
from factory_state.model import StateError


class ScheduleTests(TestCase):
    def setUp(self):
        self.temp = TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name)/'schedule.db'
        self.schedule = DevelopmentSchedule(self.path)
        self.now = datetime(2026,1,1,tzinfo=timezone.utc)
        self.packet = b'{"offline":"fake approved packet"}'
        self.digest = 'sha256:'+hashlib.sha256(self.packet).hexdigest()
        self.admit()
        self.load = Mock(return_value=self.packet)
        self.dispatch = AsyncMock(return_value='TICK_COMPLETED')

    def admit(self, **changes):
        options=dict(due_at=self.now, expires_at=self.now+timedelta(hours=1), operator_authorized=True)
        options.update(changes)
        self.schedule.admit('job-1',self.digest,**options)

    def tick(self, **changes):
        options=dict(load_packet=self.load,dispatch=self.dispatch,clock=lambda:self.now,enabled=True)
        options.update(changes)
        return asyncio.run(scheduled_tick(self.schedule,**options))

    def test_disabled_and_paused_do_not_load_or_dispatch(self):
        self.assertEqual(self.tick(enabled=False)['status'],'DISABLED')
        self.assertEqual(self.tick()['status'],'IDLE_OR_PAUSED')
        self.load.assert_not_called()
        self.dispatch.assert_not_called()

    def test_concurrent_process_connections_claim_at_most_once(self):
        self.schedule.pause(False)
        def claim(_):
            return DevelopmentSchedule(self.path).claim_due(now=self.now)
        with ThreadPoolExecutor(max_workers=8) as pool:
            claims=list(pool.map(claim,range(8)))
        self.assertEqual(sum(c is not None for c in claims),1)
        self.assertEqual(self.schedule.status('job-1'),'STARTED')

    def test_restart_never_reclaims_uncertain_started_job(self):
        self.schedule.pause(False)
        self.assertIsNotNone(self.schedule.claim_due(now=self.now))
        self.schedule=DevelopmentSchedule(self.path)
        self.admit()
        self.assertEqual(self.tick()['status'],'IDLE_OR_PAUSED')
        self.dispatch.assert_not_called()

    def test_completed_job_does_not_repeat_after_readmission(self):
        self.schedule.pause(False)
        self.assertEqual(self.tick()['status'],'COMPLETED')
        self.admit()
        self.assertEqual(self.tick()['status'],'IDLE_OR_PAUSED')
        self.dispatch.assert_awaited_once_with(self.packet)

    def test_changed_packet_and_exception_are_terminal(self):
        self.schedule.pause(False)
        self.load.return_value=b'changed'
        self.assertEqual(self.tick()['status'],'REJECTED')
        self.dispatch.assert_not_called()
        self.load.return_value=self.packet
        self.assertEqual(self.tick()['status'],'IDLE_OR_PAUSED')

    def test_dispatch_exception_is_not_retried_or_retained(self):
        self.schedule.pause(False)
        self.dispatch.side_effect=RuntimeError('secret must not persist')
        self.assertEqual(self.tick()['status'],'NEEDS_RECONCILIATION')
        self.assertEqual(self.tick()['status'],'IDLE_OR_PAUSED')
        self.dispatch.assert_awaited_once()
        self.assertNotIn(b'secret must not persist',self.path.read_bytes())

    def test_expiry_before_claim_and_after_loading_blocks_dispatch(self):
        self.schedule.pause(False)
        self.assertEqual(self.tick(clock=lambda:self.now+timedelta(hours=2))['status'],'IDLE_OR_PAUSED')
        self.assertEqual(self.schedule.status('job-1'),'EXPIRED')
        self.load.assert_not_called()

    def test_expiry_during_load_blocks_dispatch(self):
        self.schedule.pause(False)
        times=iter([self.now,self.now+timedelta(hours=2)])
        self.assertEqual(self.tick(clock=lambda:next(times))['status'],'EXPIRED')
        self.dispatch.assert_not_called()

    def test_future_due_job_waits(self):
        self.schedule.pause(False)
        self.assertEqual(self.tick(clock=lambda:self.now-timedelta(seconds=1))['status'],'IDLE_OR_PAUSED')
        self.dispatch.assert_not_called()

    def test_binding_is_immutable_and_admission_requires_operator(self):
        with self.assertRaises(StateError): self.admit(operator_authorized=False)
        with self.assertRaises(StateError): self.admit(expires_at=self.now+timedelta(hours=2))
        with self.assertRaises(StateError): self.admit(due_at=self.now.replace(tzinfo=None))

    def test_reconstructed_schedule_can_dispatch_previously_admitted_job(self):
        self.schedule.pause(False)
        self.schedule=DevelopmentSchedule(self.path)
        self.assertEqual(self.tick()['status'],'COMPLETED')
        self.dispatch.assert_awaited_once()

    def test_forged_finish_does_not_change_started_record(self):
        self.schedule.pause(False)
        claim=self.schedule.claim_due(now=self.now)
        with self.assertRaises(StateError): self.schedule.finish(dict(claim,claim='wrong'),'COMPLETED')
        self.assertEqual(self.schedule.status('job-1'),'STARTED')

    def test_same_packet_cannot_be_admitted_under_another_job(self):
        import sqlite3
        with self.assertRaises(sqlite3.IntegrityError):
            self.schedule.admit('job-2',self.digest,due_at=self.now,
                expires_at=self.now+timedelta(hours=1),operator_authorized=True)

    def test_unrecognized_dispatch_outcome_stops_without_retry(self):
        self.schedule.pause(False)
        self.dispatch.return_value='please retry'
        self.assertEqual(self.tick()['status'],'NEEDS_RECONCILIATION')
        self.assertEqual(self.tick()['status'],'IDLE_OR_PAUSED')
        self.dispatch.assert_awaited_once()

    def test_pause_after_completion_prevents_next_job(self):
        self.schedule.pause(False)
        self.assertEqual(self.tick()['status'],'COMPLETED')
        other=b'other packet'
        self.schedule.admit('job-2','sha256:'+hashlib.sha256(other).hexdigest(),
            due_at=self.now,expires_at=self.now+timedelta(hours=1),operator_authorized=True)
        self.schedule.pause(True)
        self.load.return_value=other
        self.assertEqual(self.tick()['status'],'IDLE_OR_PAUSED')
        self.dispatch.assert_awaited_once()
