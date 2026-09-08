"""Non-authoritative runtime heartbeat and stuck-task watchdog.

The watchdog observes one runtime session bound to an existing Factory lease. It
never extends a lease, mutates Factory state, restarts a worker, or terminates a
sandbox. It only validates supervisor heartbeats and returns deterministic
recovery recommendations for the authoritative controller/runtime supervisor to
act on through their own permission boundaries.

Heartbeat freshness and progress freshness are deliberately separate: a worker
that keeps emitting heartbeats while making no progress becomes STUCK rather
than HEALTHY.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import StrEnum


_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_COMMIT = re.compile(r"^[0-9a-f]{40}$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_SCHEMA_VERSION = "1.0"


class RuntimeLivenessError(RuntimeError):
    """Base class for liveness-contract failures."""


class RuntimeHeartbeatError(RuntimeLivenessError):
    """A heartbeat is stale, replayed, misbound, or structurally invalid."""


class RuntimeWatchConfigError(RuntimeLivenessError):
    """A watch binding or policy is invalid."""


def _aware(value: datetime) -> bool:
    return isinstance(value, datetime) and value.tzinfo is not None and value.utcoffset() is not None


def _require_aware(value: datetime, field: str) -> None:
    if not _aware(value):
        raise RuntimeWatchConfigError(f"{field} must be timezone-aware")


def _require_id(value: str, field: str) -> None:
    if not isinstance(value, str) or not _SAFE_ID.fullmatch(value):
        raise RuntimeWatchConfigError(f"{field} is invalid")


@dataclass(frozen=True)
class RuntimeWatchBinding:
    """Exact lease/session identity that heartbeats must match."""

    runtime_session_id: str
    task_id: str
    lease_id: str
    role_id: str
    expected_worker_identity: str
    source_commit: str
    started_at: datetime
    lease_expires_at: datetime

    def __post_init__(self) -> None:
        for name in (
            "runtime_session_id",
            "task_id",
            "lease_id",
            "role_id",
            "expected_worker_identity",
        ):
            _require_id(getattr(self, name), name)
        if not isinstance(self.source_commit, str) or not _COMMIT.fullmatch(self.source_commit):
            raise RuntimeWatchConfigError("source_commit must be a full lowercase commit SHA")
        _require_aware(self.started_at, "started_at")
        _require_aware(self.lease_expires_at, "lease_expires_at")
        if self.lease_expires_at <= self.started_at:
            raise RuntimeWatchConfigError("lease must expire after runtime session start")


@dataclass(frozen=True)
class RuntimeHeartbeat:
    """Supervisor-produced liveness observation; never authoritative evidence."""

    heartbeat_id: str
    runtime_session_id: str
    task_id: str
    lease_id: str
    role_id: str
    worker_identity: str
    source_commit: str
    heartbeat_sequence: int
    progress_sequence: int
    progress_digest: str
    observed_at: datetime

    def __post_init__(self) -> None:
        for name in (
            "heartbeat_id",
            "runtime_session_id",
            "task_id",
            "lease_id",
            "role_id",
            "worker_identity",
        ):
            value = getattr(self, name)
            if not isinstance(value, str) or not _SAFE_ID.fullmatch(value):
                raise RuntimeHeartbeatError(f"heartbeat {name} is invalid")
        if not isinstance(self.source_commit, str) or not _COMMIT.fullmatch(self.source_commit):
            raise RuntimeHeartbeatError("heartbeat source_commit is invalid")
        if (
            isinstance(self.heartbeat_sequence, bool)
            or not isinstance(self.heartbeat_sequence, int)
            or self.heartbeat_sequence < 1
            or self.heartbeat_sequence > 2**63 - 1
        ):
            raise RuntimeHeartbeatError("heartbeat_sequence is invalid")
        if (
            isinstance(self.progress_sequence, bool)
            or not isinstance(self.progress_sequence, int)
            or self.progress_sequence < 0
            or self.progress_sequence > 2**63 - 1
        ):
            raise RuntimeHeartbeatError("progress_sequence is invalid")
        if self.progress_sequence > self.heartbeat_sequence:
            raise RuntimeHeartbeatError("progress_sequence may not exceed heartbeat_sequence")
        if not isinstance(self.progress_digest, str) or not _DIGEST.fullmatch(self.progress_digest):
            raise RuntimeHeartbeatError("progress_digest is invalid")
        if not _aware(self.observed_at):
            raise RuntimeHeartbeatError("heartbeat observed_at must be timezone-aware")

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": _SCHEMA_VERSION,
            "heartbeat_id": self.heartbeat_id,
            "runtime_session_id": self.runtime_session_id,
            "task_id": self.task_id,
            "lease_id": self.lease_id,
            "role_id": self.role_id,
            "worker_identity": self.worker_identity,
            "source_commit": self.source_commit,
            "heartbeat_sequence": self.heartbeat_sequence,
            "progress_sequence": self.progress_sequence,
            "progress_digest": self.progress_digest,
            "observed_at": self.observed_at.isoformat(),
        }


@dataclass(frozen=True)
class RuntimeWatchPolicy:
    """Non-authoritative liveness/recovery thresholds."""

    startup_grace_seconds: int = 90
    stale_after_seconds: int = 120
    stuck_after_seconds: int = 300
    dead_after_seconds: int = 600
    max_clock_skew_seconds: int = 30
    max_recovery_attempts: int = 2

    def __post_init__(self) -> None:
        for name, value, low, high in (
            ("startup_grace_seconds", self.startup_grace_seconds, 1, 1800),
            ("stale_after_seconds", self.stale_after_seconds, 10, 3600),
            ("stuck_after_seconds", self.stuck_after_seconds, 30, 7200),
            ("dead_after_seconds", self.dead_after_seconds, 30, 14400),
            ("max_clock_skew_seconds", self.max_clock_skew_seconds, 0, 300),
            ("max_recovery_attempts", self.max_recovery_attempts, 0, 8),
        ):
            if isinstance(value, bool) or not isinstance(value, int) or value < low or value > high:
                raise RuntimeWatchConfigError(f"{name} must be between {low} and {high}")
        if self.startup_grace_seconds > self.stale_after_seconds:
            raise RuntimeWatchConfigError("startup grace may not exceed stale threshold")
        if self.stale_after_seconds >= self.dead_after_seconds:
            raise RuntimeWatchConfigError("stale threshold must be below dead threshold")
        if self.stuck_after_seconds <= self.stale_after_seconds:
            raise RuntimeWatchConfigError("stuck threshold must exceed stale threshold")
        if self.stuck_after_seconds >= self.dead_after_seconds:
            raise RuntimeWatchConfigError("stuck threshold must be below dead threshold")


class RuntimeLivenessStatus(StrEnum):
    STARTING = "STARTING"
    HEALTHY = "HEALTHY"
    STALE = "STALE"
    STUCK = "STUCK"
    DEAD = "DEAD"
    LEASE_EXPIRED = "LEASE_EXPIRED"


class RuntimeControllerRequest(StrEnum):
    NONE = "NONE"
    REQUEST_RUNTIME_RESTART = "REQUEST_RUNTIME_RESTART"
    REQUEST_CONTROLLER_STALL = "REQUEST_CONTROLLER_STALL"


class RuntimeSupervisorAction(StrEnum):
    NONE = "NONE"
    TERMINATE_SESSION = "TERMINATE_SESSION"


@dataclass(frozen=True)
class RuntimeWatchEvaluation:
    runtime_session_id: str
    task_id: str
    lease_id: str
    status: RuntimeLivenessStatus
    reason_code: str
    controller_request: RuntimeControllerRequest
    runtime_action: RuntimeSupervisorAction
    authoritative_recovery_count: int
    last_heartbeat_at: datetime | None
    last_progress_at: datetime | None
    evaluated_at: datetime

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": _SCHEMA_VERSION,
            "runtime_session_id": self.runtime_session_id,
            "task_id": self.task_id,
            "lease_id": self.lease_id,
            "status": self.status.value,
            "reason_code": self.reason_code,
            "controller_request": self.controller_request.value,
            "runtime_action": self.runtime_action.value,
            "authoritative_recovery_count": self.authoritative_recovery_count,
            "last_heartbeat_at": (
                self.last_heartbeat_at.isoformat() if self.last_heartbeat_at is not None else None
            ),
            "last_progress_at": (
                self.last_progress_at.isoformat() if self.last_progress_at is not None else None
            ),
            "evaluated_at": self.evaluated_at.isoformat(),
        }


class RuntimeHeartbeatTracker:
    """Validate heartbeats and derive recovery recommendations for one session."""

    def __init__(
        self,
        binding: RuntimeWatchBinding,
        policy: RuntimeWatchPolicy | None = None,
    ) -> None:
        if not isinstance(binding, RuntimeWatchBinding):
            raise RuntimeWatchConfigError("runtime watch binding is required")
        self.binding = binding
        self.policy = policy or RuntimeWatchPolicy()
        self._seen_heartbeat_ids: set[str] = set()
        self._last_heartbeat: RuntimeHeartbeat | None = None
        self._last_progress_at: datetime | None = None
        self._last_progress_sequence: int | None = None
        self._last_progress_digest: str | None = None

    @property
    def last_heartbeat(self) -> RuntimeHeartbeat | None:
        return self._last_heartbeat

    @property
    def last_progress_at(self) -> datetime | None:
        return self._last_progress_at

    def _validate_binding(self, heartbeat: RuntimeHeartbeat) -> None:
        expected = {
            "runtime_session_id": self.binding.runtime_session_id,
            "task_id": self.binding.task_id,
            "lease_id": self.binding.lease_id,
            "role_id": self.binding.role_id,
            "worker_identity": self.binding.expected_worker_identity,
            "source_commit": self.binding.source_commit,
        }
        for field, value in expected.items():
            if getattr(heartbeat, field) != value:
                raise RuntimeHeartbeatError(f"heartbeat {field} does not match runtime watch binding")

    def accept(
        self,
        heartbeat: RuntimeHeartbeat,
        *,
        received_at: datetime | None = None,
    ) -> RuntimeHeartbeat:
        if not isinstance(heartbeat, RuntimeHeartbeat):
            raise RuntimeHeartbeatError("runtime heartbeat object is required")
        received_at = received_at or datetime.now(timezone.utc)
        if not _aware(received_at):
            raise RuntimeHeartbeatError("received_at must be timezone-aware")
        self._validate_binding(heartbeat)

        if heartbeat.heartbeat_id in self._seen_heartbeat_ids:
            raise RuntimeHeartbeatError("heartbeat id replay")
        skew = timedelta(seconds=self.policy.max_clock_skew_seconds)
        if heartbeat.observed_at > received_at + skew:
            raise RuntimeHeartbeatError("heartbeat is future-dated beyond clock-skew policy")
        if heartbeat.observed_at < self.binding.started_at:
            raise RuntimeHeartbeatError("heartbeat predates runtime session")
        if heartbeat.observed_at >= self.binding.lease_expires_at:
            raise RuntimeHeartbeatError("heartbeat may not occur at or after lease expiry")

        previous = self._last_heartbeat
        if previous is not None:
            if heartbeat.heartbeat_sequence <= previous.heartbeat_sequence:
                raise RuntimeHeartbeatError("heartbeat sequence replay or regression")
            if heartbeat.observed_at <= previous.observed_at:
                raise RuntimeHeartbeatError("heartbeat timestamp replay or regression")

        previous_progress_sequence = self._last_progress_sequence
        previous_progress_digest = self._last_progress_digest
        if previous_progress_sequence is not None:
            if heartbeat.progress_sequence < previous_progress_sequence:
                raise RuntimeHeartbeatError("progress sequence regression")
            if heartbeat.progress_sequence == previous_progress_sequence:
                if heartbeat.progress_digest != previous_progress_digest:
                    raise RuntimeHeartbeatError(
                        "progress digest changed without progress-sequence advance"
                    )
            elif heartbeat.progress_digest == previous_progress_digest:
                raise RuntimeHeartbeatError(
                    "progress sequence advanced without progress-digest change"
                )

        if previous_progress_sequence is None:
            self._last_progress_at = (
                heartbeat.observed_at
                if heartbeat.progress_sequence > 0
                else self.binding.started_at
            )
        elif heartbeat.progress_sequence > previous_progress_sequence:
            self._last_progress_at = heartbeat.observed_at

        self._seen_heartbeat_ids.add(heartbeat.heartbeat_id)
        self._last_heartbeat = heartbeat
        self._last_progress_sequence = heartbeat.progress_sequence
        self._last_progress_digest = heartbeat.progress_digest
        return heartbeat

    def _recovery_request(
        self,
        authoritative_recovery_count: int,
    ) -> RuntimeControllerRequest:
        if authoritative_recovery_count < self.policy.max_recovery_attempts:
            return RuntimeControllerRequest.REQUEST_RUNTIME_RESTART
        return RuntimeControllerRequest.REQUEST_CONTROLLER_STALL

    def evaluate(
        self,
        *,
        now: datetime | None = None,
        authoritative_recovery_count: int = 0,
    ) -> RuntimeWatchEvaluation:
        now = now or datetime.now(timezone.utc)
        if not _aware(now):
            raise RuntimeWatchConfigError("watch evaluation time must be timezone-aware")
        if now < self.binding.started_at:
            raise RuntimeWatchConfigError("watch evaluation time predates runtime session")
        if (
            isinstance(authoritative_recovery_count, bool)
            or not isinstance(authoritative_recovery_count, int)
            or authoritative_recovery_count < 0
            or authoritative_recovery_count > 100
        ):
            raise RuntimeWatchConfigError("authoritative recovery count is invalid")

        last_heartbeat_at = (
            self._last_heartbeat.observed_at if self._last_heartbeat is not None else None
        )
        last_progress_at = self._last_progress_at

        if now >= self.binding.lease_expires_at:
            return RuntimeWatchEvaluation(
                runtime_session_id=self.binding.runtime_session_id,
                task_id=self.binding.task_id,
                lease_id=self.binding.lease_id,
                status=RuntimeLivenessStatus.LEASE_EXPIRED,
                reason_code="RUNTIME_LEASE_EXPIRED",
                controller_request=RuntimeControllerRequest.REQUEST_CONTROLLER_STALL,
                runtime_action=RuntimeSupervisorAction.TERMINATE_SESSION,
                authoritative_recovery_count=authoritative_recovery_count,
                last_heartbeat_at=last_heartbeat_at,
                last_progress_at=last_progress_at,
                evaluated_at=now,
            )

        if self._last_heartbeat is None:
            session_age = (now - self.binding.started_at).total_seconds()
            if session_age <= self.policy.startup_grace_seconds:
                return RuntimeWatchEvaluation(
                    runtime_session_id=self.binding.runtime_session_id,
                    task_id=self.binding.task_id,
                    lease_id=self.binding.lease_id,
                    status=RuntimeLivenessStatus.STARTING,
                    reason_code="RUNTIME_STARTUP_GRACE",
                    controller_request=RuntimeControllerRequest.NONE,
                    runtime_action=RuntimeSupervisorAction.NONE,
                    authoritative_recovery_count=authoritative_recovery_count,
                    last_heartbeat_at=None,
                    last_progress_at=None,
                    evaluated_at=now,
                )
            if session_age >= self.policy.dead_after_seconds:
                status = RuntimeLivenessStatus.DEAD
                reason = "RUNTIME_HEARTBEAT_NEVER_ARRIVED_DEAD"
            else:
                status = RuntimeLivenessStatus.STALE
                reason = "RUNTIME_HEARTBEAT_NEVER_ARRIVED"
            return RuntimeWatchEvaluation(
                runtime_session_id=self.binding.runtime_session_id,
                task_id=self.binding.task_id,
                lease_id=self.binding.lease_id,
                status=status,
                reason_code=reason,
                controller_request=self._recovery_request(authoritative_recovery_count),
                runtime_action=RuntimeSupervisorAction.TERMINATE_SESSION,
                authoritative_recovery_count=authoritative_recovery_count,
                last_heartbeat_at=None,
                last_progress_at=None,
                evaluated_at=now,
            )

        heartbeat_age = (now - self._last_heartbeat.observed_at).total_seconds()
        if heartbeat_age >= self.policy.dead_after_seconds:
            status = RuntimeLivenessStatus.DEAD
            reason = "RUNTIME_HEARTBEAT_DEAD"
        elif heartbeat_age >= self.policy.stale_after_seconds:
            status = RuntimeLivenessStatus.STALE
            reason = "RUNTIME_HEARTBEAT_STALE"
        else:
            progress_anchor = self._last_progress_at or self.binding.started_at
            progress_age = (now - progress_anchor).total_seconds()
            if progress_age >= self.policy.stuck_after_seconds:
                status = RuntimeLivenessStatus.STUCK
                reason = "RUNTIME_PROGRESS_STUCK"
            else:
                return RuntimeWatchEvaluation(
                    runtime_session_id=self.binding.runtime_session_id,
                    task_id=self.binding.task_id,
                    lease_id=self.binding.lease_id,
                    status=RuntimeLivenessStatus.HEALTHY,
                    reason_code="RUNTIME_HEALTHY",
                    controller_request=RuntimeControllerRequest.NONE,
                    runtime_action=RuntimeSupervisorAction.NONE,
                    authoritative_recovery_count=authoritative_recovery_count,
                    last_heartbeat_at=last_heartbeat_at,
                    last_progress_at=last_progress_at,
                    evaluated_at=now,
                )

        return RuntimeWatchEvaluation(
            runtime_session_id=self.binding.runtime_session_id,
            task_id=self.binding.task_id,
            lease_id=self.binding.lease_id,
            status=status,
            reason_code=reason,
            controller_request=self._recovery_request(authoritative_recovery_count),
            runtime_action=RuntimeSupervisorAction.TERMINATE_SESSION,
            authoritative_recovery_count=authoritative_recovery_count,
            last_heartbeat_at=last_heartbeat_at,
            last_progress_at=last_progress_at,
            evaluated_at=now,
        )
