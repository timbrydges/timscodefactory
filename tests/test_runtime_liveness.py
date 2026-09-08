from __future__ import annotations

import json
import sys
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from jsonschema import Draft202012Validator

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from factory_runtime.liveness import (  # noqa: E402
    RuntimeControllerRequest,
    RuntimeHeartbeat,
    RuntimeHeartbeatError,
    RuntimeHeartbeatTracker,
    RuntimeLivenessStatus,
    RuntimeSupervisorAction,
    RuntimeWatchBinding,
    RuntimeWatchConfigError,
    RuntimeWatchPolicy,
)


ROOT = Path(__file__).resolve().parents[1]
START = datetime(2026, 9, 8, 20, 0, tzinfo=timezone.utc)
COMMIT = "1" * 40
DIGEST_A = "sha256:" + "a" * 64
DIGEST_B = "sha256:" + "b" * 64


def binding(*, expires_seconds: int = 1800) -> RuntimeWatchBinding:
    return RuntimeWatchBinding(
        runtime_session_id="session-1",
        task_id="task-1",
        lease_id="lease-1",
        role_id="engineering_agent",
        expected_worker_identity="engineering_agent_service",
        source_commit=COMMIT,
        started_at=START,
        lease_expires_at=START + timedelta(seconds=expires_seconds),
    )


def heartbeat(
    sequence: int,
    *,
    progress_sequence: int = 0,
    digest: str = DIGEST_A,
    observed_seconds: int | None = None,
    heartbeat_id: str | None = None,
    worker_identity: str = "engineering_agent_service",
    lease_id: str = "lease-1",
) -> RuntimeHeartbeat:
    return RuntimeHeartbeat(
        heartbeat_id=heartbeat_id or f"heartbeat-{sequence}",
        runtime_session_id="session-1",
        task_id="task-1",
        lease_id=lease_id,
        role_id="engineering_agent",
        worker_identity=worker_identity,
        source_commit=COMMIT,
        heartbeat_sequence=sequence,
        progress_sequence=progress_sequence,
        progress_digest=digest,
        observed_at=START + timedelta(seconds=observed_seconds if observed_seconds is not None else sequence * 30),
    )


class RuntimeLivenessTests(unittest.TestCase):
    def test_heartbeat_document_matches_schema(self):
        schema = json.loads(
            (ROOT / "factory/schemas/runtime-heartbeat.schema.json").read_text(encoding="utf-8")
        )
        Draft202012Validator.check_schema(schema)
        Draft202012Validator(schema).validate(heartbeat(1).to_dict())

    def test_evaluation_document_matches_schema(self):
        schema = json.loads(
            (ROOT / "factory/schemas/runtime-watch-evaluation.schema.json").read_text(encoding="utf-8")
        )
        Draft202012Validator.check_schema(schema)
        tracker = RuntimeHeartbeatTracker(binding())
        tracker.accept(heartbeat(1, progress_sequence=1), received_at=START + timedelta(seconds=30))
        evaluation = tracker.evaluate(now=START + timedelta(seconds=60))
        Draft202012Validator(schema).validate(evaluation.to_dict())

    def test_startup_grace_without_heartbeat(self):
        tracker = RuntimeHeartbeatTracker(binding())
        result = tracker.evaluate(now=START + timedelta(seconds=60))
        self.assertEqual(result.status, RuntimeLivenessStatus.STARTING)
        self.assertEqual(result.controller_request, RuntimeControllerRequest.NONE)
        self.assertEqual(result.runtime_action, RuntimeSupervisorAction.NONE)

    def test_missing_heartbeat_becomes_stale_then_dead(self):
        tracker = RuntimeHeartbeatTracker(binding())
        stale = tracker.evaluate(now=START + timedelta(seconds=121))
        self.assertEqual(stale.status, RuntimeLivenessStatus.STALE)
        self.assertEqual(stale.controller_request, RuntimeControllerRequest.REQUEST_RUNTIME_RESTART)
        self.assertEqual(stale.runtime_action, RuntimeSupervisorAction.TERMINATE_SESSION)

        dead = tracker.evaluate(now=START + timedelta(seconds=601))
        self.assertEqual(dead.status, RuntimeLivenessStatus.DEAD)
        self.assertEqual(dead.reason_code, "RUNTIME_HEARTBEAT_NEVER_ARRIVED_DEAD")

    def test_fresh_heartbeat_with_recent_progress_is_healthy(self):
        tracker = RuntimeHeartbeatTracker(binding())
        tracker.accept(
            heartbeat(1, progress_sequence=1, observed_seconds=30),
            received_at=START + timedelta(seconds=30),
        )
        result = tracker.evaluate(now=START + timedelta(seconds=100))
        self.assertEqual(result.status, RuntimeLivenessStatus.HEALTHY)
        self.assertEqual(result.last_progress_at, START + timedelta(seconds=30))

    def test_alive_but_no_progress_becomes_stuck(self):
        policy = RuntimeWatchPolicy(
            startup_grace_seconds=60,
            stale_after_seconds=120,
            stuck_after_seconds=300,
            dead_after_seconds=600,
        )
        tracker = RuntimeHeartbeatTracker(binding(), policy)
        tracker.accept(
            heartbeat(1, progress_sequence=0, observed_seconds=30),
            received_at=START + timedelta(seconds=30),
        )
        tracker.accept(
            heartbeat(2, progress_sequence=0, observed_seconds=290),
            received_at=START + timedelta(seconds=290),
        )
        result = tracker.evaluate(now=START + timedelta(seconds=301))
        self.assertEqual(result.status, RuntimeLivenessStatus.STUCK)
        self.assertEqual(result.reason_code, "RUNTIME_PROGRESS_STUCK")
        self.assertEqual(result.controller_request, RuntimeControllerRequest.REQUEST_RUNTIME_RESTART)

    def test_progress_advance_resets_stuck_clock(self):
        tracker = RuntimeHeartbeatTracker(binding())
        tracker.accept(
            heartbeat(1, progress_sequence=0, observed_seconds=30),
            received_at=START + timedelta(seconds=30),
        )
        tracker.accept(
            heartbeat(2, progress_sequence=1, digest=DIGEST_B, observed_seconds=290),
            received_at=START + timedelta(seconds=290),
        )
        result = tracker.evaluate(now=START + timedelta(seconds=400))
        self.assertEqual(result.status, RuntimeLivenessStatus.HEALTHY)
        self.assertEqual(result.last_progress_at, START + timedelta(seconds=290))

    def test_stale_and_dead_use_heartbeat_timestamp_not_receive_time(self):
        tracker = RuntimeHeartbeatTracker(binding())
        tracker.accept(
            heartbeat(1, progress_sequence=1, observed_seconds=30),
            received_at=START + timedelta(seconds=100),
        )
        stale = tracker.evaluate(now=START + timedelta(seconds=151))
        self.assertEqual(stale.status, RuntimeLivenessStatus.STALE)
        dead = tracker.evaluate(now=START + timedelta(seconds=631))
        self.assertEqual(dead.status, RuntimeLivenessStatus.DEAD)

    def test_lease_expiry_always_requests_stall_not_restart(self):
        tracker = RuntimeHeartbeatTracker(binding(expires_seconds=400))
        tracker.accept(
            heartbeat(1, progress_sequence=1, observed_seconds=30),
            received_at=START + timedelta(seconds=30),
        )
        result = tracker.evaluate(
            now=START + timedelta(seconds=400),
            authoritative_recovery_count=0,
        )
        self.assertEqual(result.status, RuntimeLivenessStatus.LEASE_EXPIRED)
        self.assertEqual(result.controller_request, RuntimeControllerRequest.REQUEST_CONTROLLER_STALL)
        self.assertEqual(result.runtime_action, RuntimeSupervisorAction.TERMINATE_SESSION)

    def test_recovery_budget_exhaustion_requests_controller_stall(self):
        tracker = RuntimeHeartbeatTracker(binding())
        result = tracker.evaluate(
            now=START + timedelta(seconds=121),
            authoritative_recovery_count=2,
        )
        self.assertEqual(result.status, RuntimeLivenessStatus.STALE)
        self.assertEqual(result.controller_request, RuntimeControllerRequest.REQUEST_CONTROLLER_STALL)

    def test_heartbeat_id_replay_is_rejected(self):
        tracker = RuntimeHeartbeatTracker(binding())
        tracker.accept(heartbeat(1), received_at=START + timedelta(seconds=30))
        with self.assertRaises(RuntimeHeartbeatError):
            tracker.accept(
                heartbeat(2, heartbeat_id="heartbeat-1", observed_seconds=60),
                received_at=START + timedelta(seconds=60),
            )

    def test_sequence_regression_is_rejected(self):
        tracker = RuntimeHeartbeatTracker(binding())
        tracker.accept(heartbeat(2, observed_seconds=60), received_at=START + timedelta(seconds=60))
        with self.assertRaises(RuntimeHeartbeatError):
            tracker.accept(heartbeat(1, observed_seconds=90), received_at=START + timedelta(seconds=90))

    def test_timestamp_regression_is_rejected(self):
        tracker = RuntimeHeartbeatTracker(binding())
        tracker.accept(heartbeat(1, observed_seconds=60), received_at=START + timedelta(seconds=60))
        with self.assertRaises(RuntimeHeartbeatError):
            tracker.accept(heartbeat(2, observed_seconds=60), received_at=START + timedelta(seconds=61))

    def test_worker_identity_and_lease_misbinding_are_rejected(self):
        tracker = RuntimeHeartbeatTracker(binding())
        with self.assertRaises(RuntimeHeartbeatError):
            tracker.accept(
                heartbeat(1, worker_identity="wrong_worker"),
                received_at=START + timedelta(seconds=30),
            )
        with self.assertRaises(RuntimeHeartbeatError):
            tracker.accept(
                heartbeat(1, lease_id="other-lease"),
                received_at=START + timedelta(seconds=30),
            )

    def test_future_heartbeat_beyond_clock_skew_is_rejected(self):
        tracker = RuntimeHeartbeatTracker(binding())
        with self.assertRaises(RuntimeHeartbeatError):
            tracker.accept(
                heartbeat(1, observed_seconds=61),
                received_at=START + timedelta(seconds=30),
            )

    def test_heartbeat_at_or_after_lease_expiry_is_rejected(self):
        tracker = RuntimeHeartbeatTracker(binding(expires_seconds=100))
        with self.assertRaises(RuntimeHeartbeatError):
            tracker.accept(
                heartbeat(1, observed_seconds=100),
                received_at=START + timedelta(seconds=100),
            )

    def test_progress_digest_cannot_change_without_progress_advance(self):
        tracker = RuntimeHeartbeatTracker(binding())
        tracker.accept(
            heartbeat(1, progress_sequence=1, digest=DIGEST_A, observed_seconds=30),
            received_at=START + timedelta(seconds=30),
        )
        with self.assertRaises(RuntimeHeartbeatError):
            tracker.accept(
                heartbeat(2, progress_sequence=1, digest=DIGEST_B, observed_seconds=60),
                received_at=START + timedelta(seconds=60),
            )

    def test_progress_sequence_cannot_advance_with_same_digest(self):
        tracker = RuntimeHeartbeatTracker(binding())
        tracker.accept(
            heartbeat(1, progress_sequence=1, digest=DIGEST_A, observed_seconds=30),
            received_at=START + timedelta(seconds=30),
        )
        with self.assertRaises(RuntimeHeartbeatError):
            tracker.accept(
                heartbeat(2, progress_sequence=2, digest=DIGEST_A, observed_seconds=60),
                received_at=START + timedelta(seconds=60),
            )

    def test_progress_sequence_regression_is_rejected(self):
        tracker = RuntimeHeartbeatTracker(binding())
        tracker.accept(
            heartbeat(2, progress_sequence=2, digest=DIGEST_A, observed_seconds=60),
            received_at=START + timedelta(seconds=60),
        )
        with self.assertRaises(RuntimeHeartbeatError):
            tracker.accept(
                heartbeat(3, progress_sequence=1, digest=DIGEST_B, observed_seconds=90),
                received_at=START + timedelta(seconds=90),
            )

    def test_invalid_policy_ordering_fails_closed(self):
        with self.assertRaises(RuntimeWatchConfigError):
            RuntimeWatchPolicy(
                startup_grace_seconds=90,
                stale_after_seconds=120,
                stuck_after_seconds=100,
                dead_after_seconds=600,
            )

    def test_evaluation_before_session_start_fails_closed(self):
        tracker = RuntimeHeartbeatTracker(binding())
        with self.assertRaises(RuntimeWatchConfigError):
            tracker.evaluate(now=START - timedelta(seconds=1))

    def test_invalid_authoritative_recovery_count_fails_closed(self):
        tracker = RuntimeHeartbeatTracker(binding())
        with self.assertRaises(RuntimeWatchConfigError):
            tracker.evaluate(now=START + timedelta(seconds=121), authoritative_recovery_count=-1)


if __name__ == "__main__":
    unittest.main()
