"""Fail-closed state-transition model.

Agents return proposals and evidence to the controller. Only the controller
identity may call mutation methods on this model or its durable adapter.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from typing import Any, Iterable


CONTROLLER_IDENTITY = "factory_controller_service"

ALLOWED_TRANSITIONS = {
    "PAUSED": {"INTAKE"},
    "INTAKE": {"SPECIFICATION", "STALLED", "PAUSED"},
    "SPECIFICATION": {"SPEC_REVIEW", "STALLED", "PAUSED"},
    "SPEC_REVIEW": {"ARCHITECTURE", "REMEDIATION", "STALLED", "PAUSED"},
    "ARCHITECTURE": {"IMPLEMENTATION", "STALLED", "PAUSED"},
    "IMPLEMENTATION": {"INSPECTION", "STALLED", "PAUSED"},
    "INSPECTION": {"QA", "REMEDIATION", "STALLED", "PAUSED"},
    "QA": {"SECURITY_REVIEW", "REMEDIATION", "STALLED", "PAUSED"},
    "SECURITY_REVIEW": {"RELEASE_READY", "REMEDIATION", "STALLED", "PAUSED"},
    "RELEASE_READY": {"RELEASING", "PAUSED"},
    "RELEASING": {"RELEASED", "STALLED", "PAUSED"},
    "RELEASED": {"PAUSED"},
    "STALLED": {"REMEDIATION", "PAUSED"},
    "REMEDIATION": {"SPECIFICATION", "ARCHITECTURE", "IMPLEMENTATION", "INSPECTION", "QA", "SECURITY_REVIEW", "STALLED", "PAUSED"},
}


class StateError(RuntimeError):
    """Base class for deterministic state errors."""


class AuthorityError(StateError):
    pass


class InvalidTransition(StateError):
    pass


class StaleVersion(StateError):
    pass


class LeaseError(StateError):
    pass


class EvidenceError(StateError):
    pass


@dataclass(frozen=True)
class Lease:
    lease_id: str
    role_id: str
    authoritative_identity: str
    expires_at: datetime
    revoked: bool = False

    def active_at(self, now: datetime) -> bool:
        return not self.revoked and self.expires_at > now


@dataclass(frozen=True)
class Evidence:
    evidence_id: str
    producer_role: str
    producer_identity: str
    task_id: str
    lease_id: str
    source_commit: str
    artifact_digest: str
    created_at: datetime
    signature_valid: bool
    reviewer_identity: str | None = None


@dataclass(frozen=True)
class TaskState:
    factory_id: str
    task_id: str
    state: str
    version: int
    updated_at: datetime
    updated_by: str
    leases: tuple[Lease, ...] = ()
    consumed_evidence_ids: frozenset[str] = field(default_factory=frozenset)
    remediation: dict[str, Any] | None = None
    stall: dict[str, Any] | None = None


class FactoryStateMachine:
    def __init__(self, initial: TaskState):
        self._state = initial
        self._audit: list[dict[str, Any]] = []

    @property
    def state(self) -> TaskState:
        return self._state

    @property
    def audit(self) -> tuple[dict[str, Any], ...]:
        return tuple(self._audit)

    @staticmethod
    def _require_controller(caller_identity: str) -> None:
        if caller_identity != CONTROLLER_IDENTITY:
            raise AuthorityError("only the authoritative controller may mutate state")

    def issue_lease(self, caller_identity: str, lease: Lease, *, expected_version: int) -> TaskState:
        self._require_controller(caller_identity)
        self._require_version(expected_version)
        if self._state.state == "PAUSED":
            raise LeaseError("cannot issue leases while PAUSED")
        if any(item.lease_id == lease.lease_id for item in self._state.leases):
            raise LeaseError("lease id replay")
        return self._commit(replace(self._state, leases=self._state.leases + (lease,)), "LEASE_ISSUED")

    def transition(
        self,
        caller_identity: str,
        target: str,
        *,
        expected_version: int,
        evidence: Iterable[Evidence] = (),
        remediation: dict[str, Any] | None = None,
        stall: dict[str, Any] | None = None,
        now: datetime | None = None,
    ) -> TaskState:
        self._require_controller(caller_identity)
        self._require_version(expected_version)
        now = now or datetime.now(timezone.utc)
        if target not in ALLOWED_TRANSITIONS.get(self._state.state, set()):
            raise InvalidTransition(f"transition denied: {self._state.state} -> {target}")
        checked = tuple(evidence)
        self._verify_evidence(checked, now)
        if target == "REMEDIATION":
            required = {"return_state", "required_actions", "failure_code"}
            if not remediation or not required.issubset(remediation) or not remediation["required_actions"]:
                raise InvalidTransition("REMEDIATION requires deterministic return fields")
        if target == "STALLED":
            required = {"reason_code", "resume_condition", "owner_action_required"}
            if not stall or not required.issubset(stall):
                raise InvalidTransition("STALLED requires deterministic resume fields")
        leases = self._state.leases
        if target == "PAUSED":
            leases = tuple(replace(lease, revoked=True) for lease in leases)
        consumed = self._state.consumed_evidence_ids | {item.evidence_id for item in checked}
        updated = replace(
            self._state,
            state=target,
            leases=leases,
            consumed_evidence_ids=frozenset(consumed),
            remediation=remediation if target == "REMEDIATION" else None,
            stall=stall if target == "STALLED" else None,
        )
        return self._commit(updated, "STATE_TRANSITION")

    def assert_dispatch_allowed(self, caller_identity: str, lease_id: str, *, now: datetime | None = None) -> None:
        self._require_controller(caller_identity)
        now = now or datetime.now(timezone.utc)
        if self._state.state == "PAUSED":
            raise AuthorityError("dispatch is blocked while PAUSED")
        lease = next((item for item in self._state.leases if item.lease_id == lease_id), None)
        if lease is None or not lease.active_at(now):
            raise LeaseError("dispatch requires an active lease")

    def _require_version(self, expected: int) -> None:
        if self._state.version != expected:
            raise StaleVersion(f"expected version {expected}, current version {self._state.version}")

    def _verify_evidence(self, evidence: tuple[Evidence, ...], now: datetime) -> None:
        leases = {item.lease_id: item for item in self._state.leases}
        for item in evidence:
            if item.evidence_id in self._state.consumed_evidence_ids:
                raise EvidenceError("evidence replay")
            if item.task_id != self._state.task_id or not item.signature_valid:
                raise EvidenceError("evidence provenance invalid")
            lease = leases.get(item.lease_id)
            if lease is None or not lease.active_at(now):
                raise EvidenceError("evidence lease expired or revoked")
            if lease.authoritative_identity != item.producer_identity or lease.role_id != item.producer_role:
                raise EvidenceError("evidence identity is not bound to lease")
            if item.reviewer_identity is not None and item.reviewer_identity == item.producer_identity:
                raise EvidenceError("self approval denied")

    def _commit(self, updated: TaskState, event_type: str) -> TaskState:
        now = datetime.now(timezone.utc)
        updated = replace(
            updated,
            version=self._state.version + 1,
            updated_at=now,
            updated_by=CONTROLLER_IDENTITY,
        )
        self._audit.append({
            "event_type": event_type,
            "task_id": updated.task_id,
            "from_version": self._state.version,
            "to_version": updated.version,
            "state": updated.state,
            "at": now.isoformat(),
        })
        self._state = updated
        return updated

