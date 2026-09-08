"""Bounded Docker runtime supervisor/reaper below the Factory trust boundary.

The supervisor can inspect and terminate only Docker containers carrying the
exact Factory sandbox provenance labels for a supplied session handle. It also
requires a fresh liveness evaluation that explicitly recommends session
termination. It never creates/extends leases, mutates Factory state, restarts a
worker, chooses a recovery count, or decides whether the task should stall.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone

from .docker_sandbox import AsyncioProcessRunner, ProcessRunner
from .liveness import (
    RuntimeControllerRequest,
    RuntimeLivenessStatus,
    RuntimeSupervisorAction,
    RuntimeWatchEvaluation,
)


_CONTAINER_ID = re.compile(r"^[0-9a-f]{12,64}$")
_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_COMMIT = re.compile(r"^[0-9a-f]{40}$")
_SCHEMA_VERSION = "1.0"


class RuntimeSupervisorError(RuntimeError):
    """Base class for runtime-supervisor failures."""


class RuntimeResourceBindingError(RuntimeSupervisorError):
    """The Docker resource does not match the authorized Factory session."""


class RuntimeTerminationError(RuntimeSupervisorError):
    """The requested termination is stale, unauthorized, or unverifiable."""


def _aware(value: datetime) -> bool:
    return isinstance(value, datetime) and value.tzinfo is not None and value.utcoffset() is not None


def _canonical_json(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _sha256(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


@dataclass(frozen=True)
class DockerRuntimeResourceHandle:
    """Expected identity of one Factory-owned Docker sandbox resource."""

    resource_id: str
    runtime_session_id: str
    task_id: str
    lease_id: str
    role_id: str
    source_commit: str
    runner_identity: str

    def __post_init__(self) -> None:
        if not isinstance(self.resource_id, str) or not _CONTAINER_ID.fullmatch(self.resource_id):
            raise RuntimeResourceBindingError("runtime resource id is invalid")
        for name in ("runtime_session_id", "task_id", "lease_id", "role_id", "runner_identity"):
            value = getattr(self, name)
            if not isinstance(value, str) or not _SAFE_ID.fullmatch(value):
                raise RuntimeResourceBindingError(f"runtime resource {name} is invalid")
        if not isinstance(self.source_commit, str) or not _COMMIT.fullmatch(self.source_commit):
            raise RuntimeResourceBindingError("runtime resource source_commit is invalid")


@dataclass(frozen=True)
class DockerRuntimeSupervisorPolicy:
    docker_executable: str = "docker"
    supervisor_identity: str = "factory_docker_runtime_supervisor_v1"
    inspect_timeout_seconds: int = 15
    terminate_timeout_seconds: int = 30
    verify_timeout_seconds: int = 15
    max_evaluation_age_seconds: int = 60
    max_clock_skew_seconds: int = 10
    max_discovery_resources: int = 256

    def __post_init__(self) -> None:
        for name in ("docker_executable", "supervisor_identity"):
            value = getattr(self, name)
            if not isinstance(value, str) or not value or any(ch.isspace() for ch in value):
                raise RuntimeSupervisorError(f"{name} is invalid")
        for name, value, low, high in (
            ("inspect_timeout_seconds", self.inspect_timeout_seconds, 1, 120),
            ("terminate_timeout_seconds", self.terminate_timeout_seconds, 1, 120),
            ("verify_timeout_seconds", self.verify_timeout_seconds, 1, 120),
            ("max_evaluation_age_seconds", self.max_evaluation_age_seconds, 1, 300),
            ("max_clock_skew_seconds", self.max_clock_skew_seconds, 0, 60),
            ("max_discovery_resources", self.max_discovery_resources, 1, 4096),
        ):
            if isinstance(value, bool) or not isinstance(value, int) or value < low or value > high:
                raise RuntimeSupervisorError(f"{name} must be between {low} and {high}")


@dataclass(frozen=True)
class RuntimeTerminationReceipt:
    runtime_session_id: str
    task_id: str
    lease_id: str
    resource_id: str
    reason_code: str
    supervisor_identity: str
    inspected_labels_digest: str
    started_at: datetime
    finished_at: datetime

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": _SCHEMA_VERSION,
            "runtime_session_id": self.runtime_session_id,
            "task_id": self.task_id,
            "lease_id": self.lease_id,
            "resource_id": self.resource_id,
            "resource_kind": "docker_container",
            "action": "TERMINATE_SESSION",
            "reason_code": self.reason_code,
            "supervisor_identity": self.supervisor_identity,
            "inspected_labels_digest": self.inspected_labels_digest,
            "started_at": self.started_at.isoformat(),
            "finished_at": self.finished_at.isoformat(),
            "result": "TERMINATED",
        }


_REASON_BY_STATUS = {
    RuntimeLivenessStatus.STALE: {
        "RUNTIME_HEARTBEAT_NEVER_ARRIVED",
        "RUNTIME_HEARTBEAT_STALE",
    },
    RuntimeLivenessStatus.STUCK: {"RUNTIME_PROGRESS_STUCK"},
    RuntimeLivenessStatus.DEAD: {
        "RUNTIME_HEARTBEAT_NEVER_ARRIVED_DEAD",
        "RUNTIME_HEARTBEAT_DEAD",
    },
    RuntimeLivenessStatus.LEASE_EXPIRED: {"RUNTIME_LEASE_EXPIRED"},
}


class DockerRuntimeSupervisor:
    """Inspect and terminate exact Factory-labelled Docker sandbox resources."""

    def __init__(
        self,
        policy: DockerRuntimeSupervisorPolicy | None = None,
        *,
        process_runner: ProcessRunner | None = None,
    ) -> None:
        self.policy = policy or DockerRuntimeSupervisorPolicy()
        self.process_runner = process_runner or AsyncioProcessRunner()

    @staticmethod
    def _expected_labels(handle: DockerRuntimeResourceHandle) -> dict[str, str]:
        return {
            "factory.sandbox": "true",
            "factory.runtime_session_id": handle.runtime_session_id,
            "factory.request_id": handle.runtime_session_id,
            "factory.task_id": handle.task_id,
            "factory.lease_id": handle.lease_id,
            "factory.role_id": handle.role_id,
            "factory.source_commit": handle.source_commit,
            "factory.runner_identity": handle.runner_identity,
        }

    async def _inspect_labels(self, resource_id: str) -> dict[str, str]:
        result = await self.process_runner.run(
            (
                self.policy.docker_executable,
                "inspect",
                "--format={{json .Config.Labels}}",
                resource_id,
            ),
            timeout_seconds=self.policy.inspect_timeout_seconds,
        )
        if result.returncode != 0:
            raise RuntimeResourceBindingError("Docker resource could not be inspected")
        try:
            parsed = json.loads(result.stdout.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise RuntimeResourceBindingError("Docker resource labels were not valid JSON") from exc
        if not isinstance(parsed, dict) or not all(
            isinstance(key, str) and isinstance(value, str) for key, value in parsed.items()
        ):
            raise RuntimeResourceBindingError("Docker resource labels were invalid")
        return parsed

    def _validate_live_labels(
        self,
        handle: DockerRuntimeResourceHandle,
        labels: dict[str, str],
    ) -> str:
        expected = self._expected_labels(handle)
        for key, value in expected.items():
            if labels.get(key) != value:
                raise RuntimeResourceBindingError(f"Docker resource label mismatch: {key}")
        return _sha256(_canonical_json(labels))

    def _validate_evaluation(
        self,
        handle: DockerRuntimeResourceHandle,
        evaluation: RuntimeWatchEvaluation,
        *,
        now: datetime,
    ) -> None:
        if not isinstance(evaluation, RuntimeWatchEvaluation):
            raise RuntimeTerminationError("runtime watch evaluation is required")
        if not _aware(now):
            raise RuntimeTerminationError("termination time must be timezone-aware")
        if not _aware(evaluation.evaluated_at):
            raise RuntimeTerminationError("watch evaluation time must be timezone-aware")
        if evaluation.runtime_session_id != handle.runtime_session_id:
            raise RuntimeTerminationError("watch evaluation runtime session mismatch")
        if evaluation.task_id != handle.task_id:
            raise RuntimeTerminationError("watch evaluation task mismatch")
        if evaluation.lease_id != handle.lease_id:
            raise RuntimeTerminationError("watch evaluation lease mismatch")
        allowed_reasons = _REASON_BY_STATUS.get(evaluation.status)
        if allowed_reasons is None or evaluation.reason_code not in allowed_reasons:
            raise RuntimeTerminationError("watch evaluation is not a termination-eligible state")
        if evaluation.runtime_action != RuntimeSupervisorAction.TERMINATE_SESSION:
            raise RuntimeTerminationError("watch evaluation did not request session termination")
        if evaluation.controller_request == RuntimeControllerRequest.NONE:
            raise RuntimeTerminationError("termination-eligible watch evaluation lacks controller request")
        skew_seconds = (evaluation.evaluated_at - now).total_seconds()
        if skew_seconds > self.policy.max_clock_skew_seconds:
            raise RuntimeTerminationError("watch evaluation is future-dated beyond clock-skew policy")
        age_seconds = (now - evaluation.evaluated_at).total_seconds()
        if age_seconds > self.policy.max_evaluation_age_seconds:
            raise RuntimeTerminationError("watch evaluation is too old to authorize termination")

    async def inspect(
        self,
        handle: DockerRuntimeResourceHandle,
    ) -> str:
        """Return a digest of currently observed labels after exact binding validation."""

        if not isinstance(handle, DockerRuntimeResourceHandle):
            raise RuntimeResourceBindingError("runtime resource handle is required")
        labels = await self._inspect_labels(handle.resource_id)
        return self._validate_live_labels(handle, labels)

    async def terminate(
        self,
        handle: DockerRuntimeResourceHandle,
        evaluation: RuntimeWatchEvaluation,
        *,
        now: datetime | None = None,
    ) -> RuntimeTerminationReceipt:
        """Terminate exactly one proven Factory sandbox under a fresh watch decision."""

        now = now or datetime.now(timezone.utc)
        self._validate_evaluation(handle, evaluation, now=now)
        labels = await self._inspect_labels(handle.resource_id)
        labels_digest = self._validate_live_labels(handle, labels)

        started_at = datetime.now(timezone.utc)
        remove = await self.process_runner.run(
            (self.policy.docker_executable, "rm", "-f", handle.resource_id),
            timeout_seconds=self.policy.terminate_timeout_seconds,
        )
        if remove.returncode != 0:
            raise RuntimeTerminationError("Docker failed to terminate the proven runtime resource")

        verify = await self.process_runner.run(
            (
                self.policy.docker_executable,
                "ps",
                "-aq",
                "--no-trunc",
                "--filter",
                f"id={handle.resource_id}",
            ),
            timeout_seconds=self.policy.verify_timeout_seconds,
        )
        if verify.returncode != 0:
            raise RuntimeTerminationError("Docker could not verify runtime resource termination")
        remaining = tuple(
            line.strip()
            for line in verify.stdout.decode("utf-8", errors="replace").splitlines()
            if line.strip()
        )
        if remaining:
            raise RuntimeTerminationError("runtime resource still exists after Docker termination")

        finished_at = datetime.now(timezone.utc)
        return RuntimeTerminationReceipt(
            runtime_session_id=handle.runtime_session_id,
            task_id=handle.task_id,
            lease_id=handle.lease_id,
            resource_id=handle.resource_id,
            reason_code=evaluation.reason_code,
            supervisor_identity=self.policy.supervisor_identity,
            inspected_labels_digest=labels_digest,
            started_at=started_at,
            finished_at=finished_at,
        )

    async def discover_factory_sandboxes(self) -> tuple[DockerRuntimeResourceHandle, ...]:
        """Discover only fully provenance-labelled Factory sandboxes; take no action."""

        result = await self.process_runner.run(
            (
                self.policy.docker_executable,
                "ps",
                "-aq",
                "--no-trunc",
                "--filter",
                "label=factory.sandbox=true",
            ),
            timeout_seconds=self.policy.inspect_timeout_seconds,
        )
        if result.returncode != 0:
            raise RuntimeSupervisorError("Docker could not list Factory sandbox resources")
        resource_ids = tuple(
            line.strip()
            for line in result.stdout.decode("utf-8", errors="replace").splitlines()
            if line.strip()
        )
        if len(resource_ids) > self.policy.max_discovery_resources:
            raise RuntimeSupervisorError("Factory sandbox discovery exceeded configured resource cap")
        if len(set(resource_ids)) != len(resource_ids):
            raise RuntimeSupervisorError("Docker returned duplicate Factory sandbox resources")

        handles: list[DockerRuntimeResourceHandle] = []
        for resource_id in resource_ids:
            if not _CONTAINER_ID.fullmatch(resource_id):
                raise RuntimeResourceBindingError("Docker returned invalid Factory sandbox resource id")
            labels = await self._inspect_labels(resource_id)
            required = {
                "factory.sandbox",
                "factory.runtime_session_id",
                "factory.request_id",
                "factory.task_id",
                "factory.lease_id",
                "factory.role_id",
                "factory.source_commit",
                "factory.runner_identity",
            }
            if any(key not in labels for key in required):
                raise RuntimeResourceBindingError(
                    "Factory-labelled Docker resource lacks complete provenance labels"
                )
            handle = DockerRuntimeResourceHandle(
                resource_id=resource_id,
                runtime_session_id=labels["factory.runtime_session_id"],
                task_id=labels["factory.task_id"],
                lease_id=labels["factory.lease_id"],
                role_id=labels["factory.role_id"],
                source_commit=labels["factory.source_commit"],
                runner_identity=labels["factory.runner_identity"],
            )
            self._validate_live_labels(handle, labels)
            handles.append(handle)
        return tuple(handles)
