"""Tamper-evident runtime telemetry and side-effect-free trace replay.

Runtime traces contain only bounded metadata, identifiers, counters, statuses,
costs, and cryptographic digests. Raw source, prompts, model responses, logs,
credentials, patches, and diagnostic text are forbidden. Each event binds the
same runtime session identity and is hash-chained to the previous event.

Replay validates the complete chain and reconstructs a summary in memory. It
never invokes Docker, a provider, GitHub, or the Factory state controller.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
from enum import StrEnum
from typing import Iterable


_SCHEMA_VERSION = "1.0"
_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_SAFE_KEY = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
_COMMIT = re.compile(r"^[0-9a-f]{40}$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_DECIMAL = re.compile(r"^(?:0|[1-9][0-9]*)(?:\.[0-9]{1,12})?$")
_MAX_EVENT_BYTES = 64 * 1024
_MAX_TRACE_BYTES = 16 * 1024 * 1024
_MAX_EVENTS = 10_000

_FORBIDDEN_ATTRIBUTE_FRAGMENTS = (
    "raw",
    "content",
    "text",
    "body",
    "prompt",
    "response",
    "secret",
    "credential",
    "api_key",
    "authorization",
    "bearer",
    "patch",
    "diff",
)
_FORBIDDEN_LOG_KEYS = {"stdout", "stderr"}
_TOKEN_COUNT_KEYS = {"input_tokens", "output_tokens"}


class RuntimeTelemetryError(RuntimeError):
    """Base class for telemetry contract failures."""


class RuntimeTelemetryPayloadError(RuntimeTelemetryError):
    """An event attempts to store unsafe or malformed telemetry data."""


class RuntimeTraceIntegrityError(RuntimeTelemetryError):
    """A trace chain, binding, sequence, timestamp, or digest is invalid."""


class RuntimeTraceLifecycleError(RuntimeTelemetryError):
    """The event ordering violates the trace lifecycle contract."""


class RuntimeTraceEventType(StrEnum):
    SESSION_STARTED = "SESSION_STARTED"
    DETECTION_COMPLETED = "DETECTION_COMPLETED"
    PROVISIONING_COMPLETED = "PROVISIONING_COMPLETED"
    VERIFICATION_OBSERVED = "VERIFICATION_OBSERVED"
    DIAGNOSTIC_REDACTED = "DIAGNOSTIC_REDACTED"
    REPAIR_MODEL_CALL = "REPAIR_MODEL_CALL"
    REPAIR_ACTION = "REPAIR_ACTION"
    LIVENESS_EVALUATED = "LIVENESS_EVALUATED"
    TERMINATION_COMPLETED = "TERMINATION_COMPLETED"
    ESCALATED = "ESCALATED"
    SESSION_FINISHED = "SESSION_FINISHED"


_TERMINAL_EVENTS = {
    RuntimeTraceEventType.ESCALATED,
    RuntimeTraceEventType.SESSION_FINISHED,
}

_EVENT_REQUIRED_ATTRIBUTES: dict[RuntimeTraceEventType, frozenset[str]] = {
    RuntimeTraceEventType.SESSION_STARTED: frozenset({"component"}),
    RuntimeTraceEventType.DETECTION_COMPLETED: frozenset(
        {"stack", "runtime_version", "environment_spec_digest", "workspace_digest"}
    ),
    RuntimeTraceEventType.PROVISIONING_COMPLETED: frozenset(
        {"request_id", "receipt_digest", "build_log_digest", "exit_code", "timed_out"}
    ),
    RuntimeTraceEventType.VERIFICATION_OBSERVED: frozenset(
        {
            "request_id",
            "workspace_digest",
            "command_digest",
            "environment_digest",
            "stdout_digest",
            "stderr_digest",
            "exit_code",
            "timed_out",
        }
    ),
    RuntimeTraceEventType.DIAGNOSTIC_REDACTED: frozenset(
        {"diagnostic_digest", "redaction_count", "truncated"}
    ),
    RuntimeTraceEventType.REPAIR_MODEL_CALL: frozenset(
        {
            "request_id",
            "provider_profile",
            "model_selector",
            "input_tokens",
            "output_tokens",
            "cost_usd",
        }
    ),
    RuntimeTraceEventType.REPAIR_ACTION: frozenset(
        {"attempt_number", "action_digest", "workspace_digest"}
    ),
    RuntimeTraceEventType.LIVENESS_EVALUATED: frozenset(
        {"status", "reason_code", "controller_request", "runtime_action"}
    ),
    RuntimeTraceEventType.TERMINATION_COMPLETED: frozenset(
        {"resource_id_digest", "reason_code", "receipt_digest"}
    ),
    RuntimeTraceEventType.ESCALATED: frozenset({"reason_code", "attempts"}),
    RuntimeTraceEventType.SESSION_FINISHED: frozenset({"outcome", "result_digest"}),
}


def _aware(value: datetime) -> bool:
    return isinstance(value, datetime) and value.tzinfo is not None and value.utcoffset() is not None


def _canonical_json(value: object) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def _sha256(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _require_safe_id(value: str, field: str) -> None:
    if not isinstance(value, str) or not _SAFE_ID.fullmatch(value):
        raise RuntimeTraceIntegrityError(f"trace {field} is invalid")


def _validate_string_value(key: str, value: str) -> None:
    if len(value) > 512:
        raise RuntimeTelemetryPayloadError(f"telemetry attribute {key} exceeds string cap")
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in value):
        raise RuntimeTelemetryPayloadError(f"telemetry attribute {key} contains control characters")
    if key.endswith("_digest") and not _DIGEST.fullmatch(value):
        raise RuntimeTelemetryPayloadError(f"telemetry digest attribute {key} is invalid")
    if key == "cost_usd":
        if not _DECIMAL.fullmatch(value):
            raise RuntimeTelemetryPayloadError("telemetry cost_usd must be a canonical decimal string")
        try:
            parsed = Decimal(value)
        except InvalidOperation as exc:
            raise RuntimeTelemetryPayloadError("telemetry cost_usd is invalid") from exc
        if not parsed.is_finite() or parsed < 0:
            raise RuntimeTelemetryPayloadError("telemetry cost_usd must be finite and nonnegative")


def _validate_attributes(
    event_type: RuntimeTraceEventType,
    attributes: dict[str, object],
) -> dict[str, object]:
    if not isinstance(attributes, dict):
        raise RuntimeTelemetryPayloadError("telemetry attributes must be an object")
    if len(attributes) > 32:
        raise RuntimeTelemetryPayloadError("telemetry event exceeds attribute-count cap")

    normalized: dict[str, object] = {}
    for key, value in attributes.items():
        if not isinstance(key, str) or not _SAFE_KEY.fullmatch(key):
            raise RuntimeTelemetryPayloadError("telemetry attribute key is invalid")
        lowered = key.lower()
        if key in _FORBIDDEN_LOG_KEYS:
            raise RuntimeTelemetryPayloadError(f"raw {key} is forbidden in telemetry")
        if not key.endswith("_digest") and key not in _TOKEN_COUNT_KEYS:
            if any(fragment in lowered for fragment in _FORBIDDEN_ATTRIBUTE_FRAGMENTS):
                raise RuntimeTelemetryPayloadError(
                    f"telemetry attribute {key} may expose raw/sensitive content"
                )
        if isinstance(value, float) or isinstance(value, (dict, list, tuple, set, bytes, bytearray)):
            raise RuntimeTelemetryPayloadError(
                f"telemetry attribute {key} must be a flat scalar"
            )
        if value is not None and not isinstance(value, (str, int, bool)):
            raise RuntimeTelemetryPayloadError(f"telemetry attribute {key} has unsupported type")
        if isinstance(value, int) and not isinstance(value, bool):
            if value < -(2**63) or value > 2**63 - 1:
                raise RuntimeTelemetryPayloadError(f"telemetry attribute {key} integer is out of range")
            if key in _TOKEN_COUNT_KEYS and value < 0:
                raise RuntimeTelemetryPayloadError(f"telemetry attribute {key} must be nonnegative")
        if isinstance(value, str):
            _validate_string_value(key, value)
        normalized[key] = value

    required = _EVENT_REQUIRED_ATTRIBUTES[event_type]
    missing = required - set(normalized)
    if missing:
        raise RuntimeTelemetryPayloadError(
            f"telemetry {event_type.value} missing required attributes: {sorted(missing)}"
        )
    return normalized


@dataclass(frozen=True)
class RuntimeTraceBinding:
    trace_id: str
    runtime_session_id: str
    task_id: str
    lease_id: str
    role_id: str
    source_commit: str
    started_at: datetime

    def __post_init__(self) -> None:
        for name in ("trace_id", "runtime_session_id", "task_id", "lease_id", "role_id"):
            _require_safe_id(getattr(self, name), name)
        if not isinstance(self.source_commit, str) or not _COMMIT.fullmatch(self.source_commit):
            raise RuntimeTraceIntegrityError("trace source_commit is invalid")
        if not _aware(self.started_at):
            raise RuntimeTraceIntegrityError("trace started_at must be timezone-aware")


@dataclass(frozen=True)
class RuntimeTraceEvent:
    trace_id: str
    event_index: int
    event_type: RuntimeTraceEventType
    runtime_session_id: str
    task_id: str
    lease_id: str
    role_id: str
    source_commit: str
    occurred_at: datetime
    attributes: dict[str, object]
    previous_event_digest: str | None
    event_digest: str

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": _SCHEMA_VERSION,
            "trace_id": self.trace_id,
            "event_index": self.event_index,
            "event_type": self.event_type.value,
            "runtime_session_id": self.runtime_session_id,
            "task_id": self.task_id,
            "lease_id": self.lease_id,
            "role_id": self.role_id,
            "source_commit": self.source_commit,
            "occurred_at": self.occurred_at.isoformat(),
            "attributes": dict(self.attributes),
            "previous_event_digest": self.previous_event_digest,
            "event_digest": self.event_digest,
        }

    def digest_material(self) -> dict[str, object]:
        value = self.to_dict()
        del value["event_digest"]
        return value


class RuntimeTraceRecorder:
    """Build one append-only in-memory trace with deterministic hash chaining."""

    def __init__(self, binding: RuntimeTraceBinding) -> None:
        if not isinstance(binding, RuntimeTraceBinding):
            raise RuntimeTraceIntegrityError("trace binding is required")
        self.binding = binding
        self._events: list[RuntimeTraceEvent] = []

    @property
    def events(self) -> tuple[RuntimeTraceEvent, ...]:
        return tuple(self._events)

    def emit(
        self,
        event_type: RuntimeTraceEventType | str,
        attributes: dict[str, object],
        *,
        occurred_at: datetime | None = None,
    ) -> RuntimeTraceEvent:
        try:
            normalized_type = RuntimeTraceEventType(event_type)
        except (TypeError, ValueError) as exc:
            raise RuntimeTraceLifecycleError("unsupported telemetry event type") from exc
        occurred_at = occurred_at or datetime.now(timezone.utc)
        if not _aware(occurred_at):
            raise RuntimeTraceIntegrityError("telemetry event time must be timezone-aware")
        if occurred_at < self.binding.started_at:
            raise RuntimeTraceIntegrityError("telemetry event predates trace start")
        if self._events and occurred_at < self._events[-1].occurred_at:
            raise RuntimeTraceIntegrityError("telemetry event time regressed")
        if not self._events and normalized_type != RuntimeTraceEventType.SESSION_STARTED:
            raise RuntimeTraceLifecycleError("first telemetry event must be SESSION_STARTED")
        if self._events and normalized_type == RuntimeTraceEventType.SESSION_STARTED:
            raise RuntimeTraceLifecycleError("SESSION_STARTED may occur only once")
        if self._events and self._events[-1].event_type in _TERMINAL_EVENTS:
            raise RuntimeTraceLifecycleError("telemetry may not append after terminal event")
        if len(self._events) >= _MAX_EVENTS:
            raise RuntimeTraceLifecycleError("telemetry trace exceeded event-count cap")

        normalized_attributes = _validate_attributes(normalized_type, attributes)
        previous = self._events[-1].event_digest if self._events else None
        event_index = len(self._events) + 1
        material = {
            "schema_version": _SCHEMA_VERSION,
            "trace_id": self.binding.trace_id,
            "event_index": event_index,
            "event_type": normalized_type.value,
            "runtime_session_id": self.binding.runtime_session_id,
            "task_id": self.binding.task_id,
            "lease_id": self.binding.lease_id,
            "role_id": self.binding.role_id,
            "source_commit": self.binding.source_commit,
            "occurred_at": occurred_at.isoformat(),
            "attributes": normalized_attributes,
            "previous_event_digest": previous,
        }
        event_digest = _sha256(_canonical_json(material))
        event = RuntimeTraceEvent(
            trace_id=self.binding.trace_id,
            event_index=event_index,
            event_type=normalized_type,
            runtime_session_id=self.binding.runtime_session_id,
            task_id=self.binding.task_id,
            lease_id=self.binding.lease_id,
            role_id=self.binding.role_id,
            source_commit=self.binding.source_commit,
            occurred_at=occurred_at,
            attributes=normalized_attributes,
            previous_event_digest=previous,
            event_digest=event_digest,
        )
        encoded = _canonical_json(event.to_dict())
        if len(encoded) > _MAX_EVENT_BYTES:
            raise RuntimeTelemetryPayloadError("telemetry event exceeds byte cap")
        self._events.append(event)
        return event


@dataclass(frozen=True)
class RuntimeTraceReplayResult:
    trace_id: str
    runtime_session_id: str
    event_count: int
    final_event_digest: str
    terminal_status: str
    terminal_reason: str | None
    verification_observations: int
    repair_actions: int
    model_calls: int
    liveness_evaluations: int
    terminations: int
    total_provider_cost_usd: Decimal


def _event_from_dict(value: dict[str, object]) -> RuntimeTraceEvent:
    expected = {
        "schema_version",
        "trace_id",
        "event_index",
        "event_type",
        "runtime_session_id",
        "task_id",
        "lease_id",
        "role_id",
        "source_commit",
        "occurred_at",
        "attributes",
        "previous_event_digest",
        "event_digest",
    }
    if set(value) != expected or value.get("schema_version") != _SCHEMA_VERSION:
        raise RuntimeTraceIntegrityError("telemetry event keys/schema version are invalid")
    try:
        event_type = RuntimeTraceEventType(value["event_type"])
        occurred_at = datetime.fromisoformat(value["occurred_at"])
    except (TypeError, ValueError) as exc:
        raise RuntimeTraceIntegrityError("telemetry event type/timestamp is invalid") from exc
    if not _aware(occurred_at):
        raise RuntimeTraceIntegrityError("telemetry event timestamp must be timezone-aware")
    attributes = value["attributes"]
    if not isinstance(attributes, dict):
        raise RuntimeTelemetryPayloadError("telemetry attributes must be an object")
    normalized = _validate_attributes(event_type, attributes)
    previous = value["previous_event_digest"]
    if previous is not None and (not isinstance(previous, str) or not _DIGEST.fullmatch(previous)):
        raise RuntimeTraceIntegrityError("previous telemetry digest is invalid")
    event_digest = value["event_digest"]
    if not isinstance(event_digest, str) or not _DIGEST.fullmatch(event_digest):
        raise RuntimeTraceIntegrityError("telemetry event digest is invalid")
    index = value["event_index"]
    if isinstance(index, bool) or not isinstance(index, int) or index < 1 or index > _MAX_EVENTS:
        raise RuntimeTraceIntegrityError("telemetry event index is invalid")
    for key in ("trace_id", "runtime_session_id", "task_id", "lease_id", "role_id"):
        if not isinstance(value[key], str):
            raise RuntimeTraceIntegrityError(f"telemetry event {key} is invalid")
        _require_safe_id(value[key], key)
    source_commit = value["source_commit"]
    if not isinstance(source_commit, str) or not _COMMIT.fullmatch(source_commit):
        raise RuntimeTraceIntegrityError("telemetry source_commit is invalid")
    return RuntimeTraceEvent(
        trace_id=value["trace_id"],
        event_index=index,
        event_type=event_type,
        runtime_session_id=value["runtime_session_id"],
        task_id=value["task_id"],
        lease_id=value["lease_id"],
        role_id=value["role_id"],
        source_commit=source_commit,
        occurred_at=occurred_at,
        attributes=normalized,
        previous_event_digest=previous,
        event_digest=event_digest,
    )


def validate_runtime_trace(
    events: Iterable[RuntimeTraceEvent],
) -> tuple[RuntimeTraceEvent, ...]:
    checked = tuple(events)
    if not checked:
        raise RuntimeTraceIntegrityError("runtime trace is empty")
    if len(checked) > _MAX_EVENTS:
        raise RuntimeTraceIntegrityError("runtime trace exceeds event-count cap")
    first = checked[0]
    if not isinstance(first, RuntimeTraceEvent):
        raise RuntimeTraceIntegrityError("runtime trace contains invalid event type")
    if first.event_type != RuntimeTraceEventType.SESSION_STARTED:
        raise RuntimeTraceLifecycleError("runtime trace must begin with SESSION_STARTED")

    binding = (
        first.trace_id,
        first.runtime_session_id,
        first.task_id,
        first.lease_id,
        first.role_id,
        first.source_commit,
    )
    previous_digest: str | None = None
    previous_time: datetime | None = None
    terminal_seen = False
    total_bytes = 0
    liveness_reason_for_termination: str | None = None

    for expected_index, event in enumerate(checked, start=1):
        if not isinstance(event, RuntimeTraceEvent):
            raise RuntimeTraceIntegrityError("runtime trace contains invalid event type")
        if event.event_index != expected_index:
            raise RuntimeTraceIntegrityError("runtime trace event indexes are not contiguous")
        current_binding = (
            event.trace_id,
            event.runtime_session_id,
            event.task_id,
            event.lease_id,
            event.role_id,
            event.source_commit,
        )
        if current_binding != binding:
            raise RuntimeTraceIntegrityError("runtime trace event binding drifted")
        if event.previous_event_digest != previous_digest:
            raise RuntimeTraceIntegrityError("runtime trace previous-event digest chain is broken")
        if previous_time is not None and event.occurred_at < previous_time:
            raise RuntimeTraceIntegrityError("runtime trace event timestamps regressed")
        if expected_index > 1 and event.event_type == RuntimeTraceEventType.SESSION_STARTED:
            raise RuntimeTraceLifecycleError("runtime trace contains repeated SESSION_STARTED")
        if terminal_seen:
            raise RuntimeTraceLifecycleError("runtime trace contains events after terminal event")

        validated_attributes = _validate_attributes(event.event_type, event.attributes)
        if validated_attributes != event.attributes:
            raise RuntimeTraceIntegrityError("runtime trace attributes are not canonical")
        expected_digest = _sha256(_canonical_json(event.digest_material()))
        if event.event_digest != expected_digest:
            raise RuntimeTraceIntegrityError("runtime trace event digest mismatch")
        encoded = _canonical_json(event.to_dict())
        if len(encoded) > _MAX_EVENT_BYTES:
            raise RuntimeTraceIntegrityError("runtime trace event exceeds byte cap")
        total_bytes += len(encoded) + 1
        if total_bytes > _MAX_TRACE_BYTES:
            raise RuntimeTraceIntegrityError("runtime trace exceeds total byte cap")

        if event.event_type == RuntimeTraceEventType.LIVENESS_EVALUATED:
            if event.attributes.get("runtime_action") == "TERMINATE_SESSION":
                reason = event.attributes.get("reason_code")
                liveness_reason_for_termination = reason if isinstance(reason, str) else None
        elif event.event_type == RuntimeTraceEventType.TERMINATION_COMPLETED:
            reason = event.attributes.get("reason_code")
            if liveness_reason_for_termination is None or reason != liveness_reason_for_termination:
                raise RuntimeTraceLifecycleError(
                    "runtime termination lacks matching prior liveness termination decision"
                )
            liveness_reason_for_termination = None

        if event.event_type in _TERMINAL_EVENTS:
            terminal_seen = True
        previous_digest = event.event_digest
        previous_time = event.occurred_at

    return checked


def serialize_runtime_trace(events: Iterable[RuntimeTraceEvent]) -> bytes:
    checked = validate_runtime_trace(events)
    encoded = b"\n".join(_canonical_json(event.to_dict()) for event in checked) + b"\n"
    if len(encoded) > _MAX_TRACE_BYTES:
        raise RuntimeTraceIntegrityError("runtime trace exceeds serialized byte cap")
    return encoded


def parse_runtime_trace_jsonl(raw: bytes) -> tuple[RuntimeTraceEvent, ...]:
    if not isinstance(raw, bytes):
        raise RuntimeTraceIntegrityError("runtime trace JSONL must be bytes")
    if not raw or len(raw) > _MAX_TRACE_BYTES:
        raise RuntimeTraceIntegrityError("runtime trace JSONL size is invalid")
    if not raw.endswith(b"\n"):
        raise RuntimeTraceIntegrityError("runtime trace JSONL must end with newline")
    lines = raw.splitlines()
    if not lines or len(lines) > _MAX_EVENTS:
        raise RuntimeTraceIntegrityError("runtime trace JSONL event count is invalid")
    events: list[RuntimeTraceEvent] = []
    for line in lines:
        if not line or len(line) > _MAX_EVENT_BYTES:
            raise RuntimeTraceIntegrityError("runtime trace JSONL contains invalid event line")
        try:
            value = json.loads(line.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise RuntimeTraceIntegrityError("runtime trace JSONL contains invalid JSON") from exc
        if not isinstance(value, dict):
            raise RuntimeTraceIntegrityError("runtime trace JSONL event must be an object")
        events.append(_event_from_dict(value))
    return validate_runtime_trace(events)


def replay_runtime_trace(events: Iterable[RuntimeTraceEvent]) -> RuntimeTraceReplayResult:
    """Validate then reconstruct a runtime summary without any side effects."""

    checked = validate_runtime_trace(events)
    total_cost = Decimal("0")
    verification_observations = 0
    repair_actions = 0
    model_calls = 0
    liveness_evaluations = 0
    terminations = 0
    terminal_status = "INCOMPLETE"
    terminal_reason: str | None = None

    for event in checked:
        if event.event_type == RuntimeTraceEventType.VERIFICATION_OBSERVED:
            verification_observations += 1
        elif event.event_type == RuntimeTraceEventType.REPAIR_ACTION:
            repair_actions += 1
        elif event.event_type == RuntimeTraceEventType.REPAIR_MODEL_CALL:
            model_calls += 1
            cost = event.attributes["cost_usd"]
            assert isinstance(cost, str)
            total_cost += Decimal(cost)
        elif event.event_type == RuntimeTraceEventType.LIVENESS_EVALUATED:
            liveness_evaluations += 1
        elif event.event_type == RuntimeTraceEventType.TERMINATION_COMPLETED:
            terminations += 1
        elif event.event_type == RuntimeTraceEventType.ESCALATED:
            terminal_status = "ESCALATED"
            reason = event.attributes.get("reason_code")
            terminal_reason = reason if isinstance(reason, str) else None
        elif event.event_type == RuntimeTraceEventType.SESSION_FINISHED:
            terminal_status = "SUCCEEDED"
            outcome = event.attributes.get("outcome")
            terminal_reason = outcome if isinstance(outcome, str) else None

    return RuntimeTraceReplayResult(
        trace_id=checked[0].trace_id,
        runtime_session_id=checked[0].runtime_session_id,
        event_count=len(checked),
        final_event_digest=checked[-1].event_digest,
        terminal_status=terminal_status,
        terminal_reason=terminal_reason,
        verification_observations=verification_observations,
        repair_actions=repair_actions,
        model_calls=model_calls,
        liveness_evaluations=liveness_evaluations,
        terminations=terminations,
        total_provider_cost_usd=total_cost,
    )
