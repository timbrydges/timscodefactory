"""Automatic telemetry artifacts for brokered CI-repair execution.

This module converts one completed, non-authoritative repair attempt into the
Factory's tamper-evident runtime trace format. It never inspects raw prompts,
source contents, stdout/stderr text, credentials, or provider responses.

Failure fingerprints are exact deterministic fingerprints over bound runtime
metadata and output digests. They are intended for safe deduplication/replay;
semantic clustering is deliberately a separate future layer.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from decimal import Decimal
from typing import Protocol

from .pipeline import RuntimeObservation
from .provider_broker import ProviderBrokerCallRecord
from .repair import RepairEscalation, RepairOutcome, RepairRequest, VerifiedRepairCandidate
from .sandbox import command_digest
from .telemetry import (
    RuntimeTraceBinding,
    RuntimeTraceEvent,
    RuntimeTraceEventType,
    RuntimeTraceRecorder,
    RuntimeTraceReplayResult,
    replay_runtime_trace,
    serialize_runtime_trace,
    validate_runtime_trace,
)


_FINGERPRINT_VERSION = "factory-failure-fingerprint-v1"
_TRACE_COMPONENT = "brokered_ci_repair"


class BrokeredRepairTraceError(RuntimeError):
    """A repair result could not be represented as a trustworthy trace."""


def _canonical_json(value: object) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def _sha256(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _digest_fields(*values: object) -> str:
    return _sha256(_canonical_json(list(values)))


@dataclass(frozen=True)
class FailureFingerprint:
    version: str
    digest: str
    command_digest: str
    environment_digest: str | None
    stdout_digest: str | None
    stderr_digest: str | None
    exit_code: int | None
    timed_out: bool | None


def fingerprint_runtime_failure(observation: RuntimeObservation) -> FailureFingerprint:
    """Create an exact metadata-only fingerprint for one bound runtime failure."""

    if not isinstance(observation, RuntimeObservation):
        raise BrokeredRepairTraceError("runtime observation is required for failure fingerprint")
    receipt = observation.verification.receipt
    if receipt.exit_code == 0 and not receipt.timed_out:
        raise BrokeredRepairTraceError("failure fingerprint requires a failed verification")

    material = {
        "version": _FINGERPRINT_VERSION,
        "command_digest": observation.verification_request.command_digest,
        "environment_digest": observation.verification_request.environment_digest,
        "stdout_digest": receipt.stdout_digest,
        "stderr_digest": receipt.stderr_digest,
        "exit_code": receipt.exit_code,
        "timed_out": receipt.timed_out,
        "stack": observation.detection.stack,
        "runtime_version": observation.detection.runtime_version,
        "environment_spec_digest": observation.detection.spec.digest,
    }
    return FailureFingerprint(
        version=_FINGERPRINT_VERSION,
        digest=_sha256(_canonical_json(material)),
        command_digest=observation.verification_request.command_digest,
        environment_digest=observation.verification_request.environment_digest,
        stdout_digest=receipt.stdout_digest,
        stderr_digest=receipt.stderr_digest,
        exit_code=receipt.exit_code,
        timed_out=receipt.timed_out,
    )


def fingerprint_repair_outcome(
    request: RepairRequest,
    outcome: RepairOutcome,
) -> FailureFingerprint:
    """Fingerprint either a bound runtime failure or an early infrastructure failure."""

    if outcome.initial_failure is not None:
        return fingerprint_runtime_failure(outcome.initial_failure)
    if not isinstance(outcome, RepairEscalation):
        raise BrokeredRepairTraceError("verified repair is missing its initial failure observation")
    cmd_digest = command_digest(request.command)
    material = {
        "version": _FINGERPRINT_VERSION,
        "command_digest": cmd_digest,
        "unbound_failure_reason": outcome.reason.value,
    }
    return FailureFingerprint(
        version=_FINGERPRINT_VERSION,
        digest=_sha256(_canonical_json(material)),
        command_digest=cmd_digest,
        environment_digest=None,
        stdout_digest=None,
        stderr_digest=None,
        exit_code=None,
        timed_out=None,
    )


@dataclass(frozen=True)
class BrokeredRepairTraceArtifact:
    repair_id: str
    trace_id: str
    failure_fingerprint: FailureFingerprint
    events: tuple[RuntimeTraceEvent, ...]
    jsonl: bytes
    replay: RuntimeTraceReplayResult


class BrokeredRepairTraceStore(Protocol):
    def store(self, artifact: BrokeredRepairTraceArtifact) -> None:
        ...


class InMemoryBrokeredRepairTraceStore:
    """Bounded-process reference sink for dry runs/tests.

    Persistent production storage remains a separate deployment concern.
    """

    def __init__(self, *, max_items: int = 256) -> None:
        if isinstance(max_items, bool) or not isinstance(max_items, int) or not (1 <= max_items <= 4096):
            raise ValueError("max_items must be between 1 and 4096")
        self.max_items = max_items
        self._items: dict[str, BrokeredRepairTraceArtifact] = {}

    def store(self, artifact: BrokeredRepairTraceArtifact) -> None:
        if not isinstance(artifact, BrokeredRepairTraceArtifact):
            raise BrokeredRepairTraceError("trace store requires a BrokeredRepairTraceArtifact")
        existing = self._items.get(artifact.trace_id)
        if existing is not None:
            if existing != artifact:
                raise BrokeredRepairTraceError("trace_id collision with different artifact")
            return
        if len(self._items) >= self.max_items:
            raise BrokeredRepairTraceError("in-memory trace store capacity exhausted")
        self._items[artifact.trace_id] = artifact

    def get(self, trace_id: str) -> BrokeredRepairTraceArtifact | None:
        return self._items.get(trace_id)

    @property
    def artifacts(self) -> tuple[BrokeredRepairTraceArtifact, ...]:
        return tuple(self._items.values())


def _trace_id(request: RepairRequest, started_at: datetime) -> str:
    seed = {
        "repair_id": request.repair_id,
        "task_id": request.task_id,
        "lease_id": request.lease_id,
        "role_id": request.role_id,
        "source_commit": request.source_commit,
        "started_at": started_at.isoformat(),
    }
    return "trace-" + hashlib.sha256(_canonical_json(seed)).hexdigest()[:32]


def _provisioning_receipt_digest(observation: RuntimeObservation) -> str:
    receipt = observation.provisioning.receipt
    return _digest_fields(
        receipt.request_id,
        receipt.task_id,
        receipt.lease_id,
        receipt.role_id,
        receipt.source_commit,
        receipt.workspace_digest,
        receipt.environment_spec_digest,
        receipt.provisioner_identity,
        receipt.result_image_ref,
        receipt.started_at.isoformat(),
        receipt.finished_at.isoformat(),
        receipt.exit_code,
        receipt.timed_out,
        receipt.build_log_digest,
    )


def _diagnostic_digest(observation: RuntimeObservation) -> str | None:
    diagnostics = observation.diagnostics
    if diagnostics is None:
        return None
    return _digest_fields(
        diagnostics.request_digest,
        diagnostics.stdout_digest,
        diagnostics.stderr_digest,
        diagnostics.redaction_count,
        diagnostics.stdout_truncated,
        diagnostics.stderr_truncated,
        diagnostics.sanitizer_version,
    )


def _emit_observation(recorder: RuntimeTraceRecorder, observation: RuntimeObservation) -> None:
    detection = observation.detection
    recorder.emit(
        RuntimeTraceEventType.DETECTION_COMPLETED,
        {
            "stack": detection.stack,
            "runtime_version": detection.runtime_version or "unspecified",
            "environment_spec_digest": detection.spec.digest,
            "workspace_digest": observation.workspace_digest,
        },
    )
    provisioning = observation.provisioning.receipt
    recorder.emit(
        RuntimeTraceEventType.PROVISIONING_COMPLETED,
        {
            "request_id": provisioning.request_id,
            "receipt_digest": _provisioning_receipt_digest(observation),
            "build_log_digest": provisioning.build_log_digest,
            "exit_code": provisioning.exit_code,
            "timed_out": provisioning.timed_out,
        },
    )
    verification = observation.verification.receipt
    recorder.emit(
        RuntimeTraceEventType.VERIFICATION_OBSERVED,
        {
            "request_id": verification.request_id,
            "workspace_digest": verification.workspace_digest,
            "command_digest": verification.command_digest,
            "environment_digest": verification.environment_digest,
            "stdout_digest": verification.stdout_digest,
            "stderr_digest": verification.stderr_digest,
            "exit_code": verification.exit_code,
            "timed_out": verification.timed_out,
        },
    )
    diagnostic_digest = _diagnostic_digest(observation)
    if diagnostic_digest is not None:
        diagnostics = observation.diagnostics
        assert diagnostics is not None
        recorder.emit(
            RuntimeTraceEventType.DIAGNOSTIC_REDACTED,
            {
                "diagnostic_digest": diagnostic_digest,
                "redaction_count": diagnostics.redaction_count,
                "truncated": diagnostics.stdout_truncated or diagnostics.stderr_truncated,
            },
        )


def _emit_model_calls(
    recorder: RuntimeTraceRecorder,
    calls: tuple[ProviderBrokerCallRecord, ...],
) -> None:
    for call in calls:
        recorder.emit(
            RuntimeTraceEventType.REPAIR_MODEL_CALL,
            {
                "request_id": call.request_id,
                "provider_profile": call.provider_profile,
                "model_selector": call.model_selector,
                "input_tokens": call.usage.input_tokens,
                "output_tokens": call.usage.output_tokens,
                "cost_usd": format(call.usage.cost_usd, "f"),
            },
        )


def _terminal_workspace_digest(outcome: RepairOutcome) -> str | None:
    if isinstance(outcome, VerifiedRepairCandidate):
        return outcome.workspace_digest
    if isinstance(outcome, RepairEscalation):
        if outcome.last_failure is not None:
            return outcome.last_failure.workspace_digest
        if outcome.initial_failure is not None:
            return outcome.initial_failure.workspace_digest
    return None


def _emit_actions(recorder: RuntimeTraceRecorder, outcome: RepairOutcome) -> None:
    workspace_digest = _terminal_workspace_digest(outcome)
    if workspace_digest is None:
        return
    for attempt_number, action in enumerate(outcome.actions, start=1):
        recorder.emit(
            RuntimeTraceEventType.REPAIR_ACTION,
            {
                "attempt_number": attempt_number,
                "action_digest": _sha256(action.summary.encode("utf-8")),
                "workspace_digest": workspace_digest,
            },
        )


def _emit_terminal_verification(
    recorder: RuntimeTraceRecorder,
    outcome: RepairOutcome,
    initial: RuntimeObservation | None,
) -> None:
    if isinstance(outcome, VerifiedRepairCandidate):
        receipt = outcome.verification.receipt
        recorder.emit(
            RuntimeTraceEventType.VERIFICATION_OBSERVED,
            {
                "request_id": receipt.request_id,
                "workspace_digest": receipt.workspace_digest,
                "command_digest": receipt.command_digest,
                "environment_digest": receipt.environment_digest,
                "stdout_digest": receipt.stdout_digest,
                "stderr_digest": receipt.stderr_digest,
                "exit_code": receipt.exit_code,
                "timed_out": receipt.timed_out,
            },
        )
        return
    if isinstance(outcome, RepairEscalation) and outcome.last_failure is not None:
        last = outcome.last_failure
        if initial is None or last.verification.receipt.request_id != initial.verification.receipt.request_id:
            verification = last.verification.receipt
            recorder.emit(
                RuntimeTraceEventType.VERIFICATION_OBSERVED,
                {
                    "request_id": verification.request_id,
                    "workspace_digest": verification.workspace_digest,
                    "command_digest": verification.command_digest,
                    "environment_digest": verification.environment_digest,
                    "stdout_digest": verification.stdout_digest,
                    "stderr_digest": verification.stderr_digest,
                    "exit_code": verification.exit_code,
                    "timed_out": verification.timed_out,
                },
            )
            diagnostic_digest = _diagnostic_digest(last)
            if diagnostic_digest is not None:
                diagnostics = last.diagnostics
                assert diagnostics is not None
                recorder.emit(
                    RuntimeTraceEventType.DIAGNOSTIC_REDACTED,
                    {
                        "diagnostic_digest": diagnostic_digest,
                        "redaction_count": diagnostics.redaction_count,
                        "truncated": diagnostics.stdout_truncated or diagnostics.stderr_truncated,
                    },
                )


def _outcome_digest(outcome: RepairOutcome) -> str:
    if isinstance(outcome, VerifiedRepairCandidate):
        return _digest_fields(
            "VERIFIED_REPAIR",
            outcome.workspace_digest,
            outcome.attempt_number,
            outcome.verification.receipt.request_id,
            outcome.verification.receipt.stdout_digest,
            outcome.verification.receipt.stderr_digest,
        )
    assert isinstance(outcome, RepairEscalation)
    last_request = (
        outcome.last_failure.verification.receipt.request_id
        if outcome.last_failure is not None
        else None
    )
    return _digest_fields(
        "ESCALATED",
        outcome.reason.value,
        outcome.attempts,
        last_request,
    )


def build_brokered_repair_trace(
    request: RepairRequest,
    outcome: RepairOutcome,
    provider_calls: tuple[ProviderBrokerCallRecord, ...],
    *,
    started_at: datetime | None = None,
) -> BrokeredRepairTraceArtifact:
    """Build, validate, serialize and replay one completed repair trace."""

    started_at = started_at or datetime.now(timezone.utc)
    if started_at.tzinfo is None or started_at.utcoffset() is None:
        raise BrokeredRepairTraceError("trace start time must be timezone-aware")

    initial = outcome.initial_failure
    fingerprint = fingerprint_repair_outcome(request, outcome)
    trace_id = _trace_id(request, started_at)
    recorder = RuntimeTraceRecorder(
        RuntimeTraceBinding(
            trace_id=trace_id,
            runtime_session_id=request.repair_id,
            task_id=request.task_id,
            lease_id=request.lease_id,
            role_id=request.role_id,
            source_commit=request.source_commit,
            started_at=started_at,
        )
    )
    recorder.emit(
        RuntimeTraceEventType.SESSION_STARTED,
        {
            "component": _TRACE_COMPONENT,
            "failure_fingerprint_digest": fingerprint.digest,
            "failure_fingerprint_version": fingerprint.version,
            "failure_command_digest": fingerprint.command_digest,
        },
    )
    if initial is not None:
        _emit_observation(recorder, initial)
    _emit_model_calls(recorder, provider_calls)
    _emit_actions(recorder, outcome)
    _emit_terminal_verification(recorder, outcome, initial)

    if isinstance(outcome, VerifiedRepairCandidate):
        recorder.emit(
            RuntimeTraceEventType.SESSION_FINISHED,
            {
                "outcome": "VERIFIED_REPAIR",
                "result_digest": _outcome_digest(outcome),
            },
        )
    else:
        assert isinstance(outcome, RepairEscalation)
        recorder.emit(
            RuntimeTraceEventType.ESCALATED,
            {
                "reason_code": outcome.reason.value,
                "attempts": outcome.attempts,
            },
        )

    events = validate_runtime_trace(recorder.events)
    jsonl = serialize_runtime_trace(events)
    replay = replay_runtime_trace(events)
    expected_status = "SUCCEEDED" if isinstance(outcome, VerifiedRepairCandidate) else "ESCALATED"
    if replay.terminal_status != expected_status:
        raise BrokeredRepairTraceError("trace replay terminal status disagrees with repair outcome")
    expected_cost = sum((item.usage.cost_usd for item in provider_calls), Decimal("0"))
    if replay.total_provider_cost_usd != expected_cost:
        raise BrokeredRepairTraceError("trace replay provider cost disagrees with broker records")
    return BrokeredRepairTraceArtifact(
        repair_id=request.repair_id,
        trace_id=trace_id,
        failure_fingerprint=fingerprint,
        events=events,
        jsonl=jsonl,
        replay=replay,
    )
