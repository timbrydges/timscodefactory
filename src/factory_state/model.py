"""Fail-closed state-transition model.

Agents return proposals and evidence to the controller. The controller handles
normal orchestration; Tim, the human Factory Owner, retains explicit authority
to override gates, change state, dispatch, pause, or stop the Factory.
"""

from __future__ import annotations

import re
from copy import deepcopy
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from typing import Any, Iterable


CONTROLLER_IDENTITY = "factory_controller_service"
OWNER_IDENTITY = "tim_brydges"

ROLE_IDENTITIES = {
    "deep_security_reviewer": "deep_security_reviewer_service",
    "engineering_agent": "engineering_agent_service",
    "independent_inspector": "independent_inspector_service",
    "product_spec_author": "product_spec_author_service",
    "product_spec_reviewer": "product_spec_reviewer_service",
    "qa_engineer": "qa_engineer_service",
    "release_automation": "github_actions_production_environment",
    "software_architect": "software_architect_service",
    "specialist_reviewer": "specialist_reviewer_dynamic_identity",
}

ROLE_ALLOWED_STATES = {
    "deep_security_reviewer": {"SECURITY_REVIEW"},
    "engineering_agent": {"IMPLEMENTATION", "REMEDIATION"},
    "independent_inspector": {"INSPECTION", "REMEDIATION"},
    "product_spec_author": {"SPECIFICATION", "REMEDIATION"},
    "product_spec_reviewer": {"SPEC_REVIEW"},
    "qa_engineer": {"QA", "REMEDIATION"},
    "release_automation": {"RELEASE_READY", "RELEASING"},
    "software_architect": {"ARCHITECTURE", "REMEDIATION"},
    "specialist_reviewer": {"SPEC_REVIEW", "ARCHITECTURE", "INSPECTION", "SECURITY_REVIEW"},
}

# Automated gate advances require evidence from the role that owns the work or
# verdict at that boundary. Tim's owner_override path intentionally bypasses
# these agent controls while remaining audited.
REQUIRED_EVIDENCE_ROLES = {
    ("SPECIFICATION", "SPEC_REVIEW"): {"product_spec_author"},
    ("SPEC_REVIEW", "ARCHITECTURE"): {"product_spec_reviewer"},
    ("SPEC_REVIEW", "REMEDIATION"): {"product_spec_reviewer"},
    ("ARCHITECTURE", "IMPLEMENTATION"): {"software_architect"},
    ("IMPLEMENTATION", "INSPECTION"): {"engineering_agent"},
    ("INSPECTION", "QA"): {"independent_inspector"},
    ("INSPECTION", "REMEDIATION"): {"independent_inspector"},
    ("QA", "SECURITY_REVIEW"): {"qa_engineer"},
    ("QA", "REMEDIATION"): {"qa_engineer"},
    ("SECURITY_REVIEW", "RELEASE_READY"): {"deep_security_reviewer"},
    ("SECURITY_REVIEW", "REMEDIATION"): {"deep_security_reviewer"},
    ("RELEASE_READY", "RELEASING"): {"release_automation"},
    ("RELEASING", "RELEASED"): {"release_automation"},
}

SHA256_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
COMMIT_SHA = re.compile(r"^[0-9a-f]{40}$")
SAFE_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
REMEDIATION_RETURN_STATES = {
    "SPECIFICATION",
    "ARCHITECTURE",
    "IMPLEMENTATION",
    "INSPECTION",
    "QA",
    "SECURITY_REVIEW",
}

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

    def __post_init__(self) -> None:
        if not isinstance(self.lease_id, str) or not SAFE_IDENTIFIER.fullmatch(self.lease_id):
            raise LeaseError("lease id is invalid")
        if not isinstance(self.role_id, str) or not isinstance(self.authoritative_identity, str):
            raise LeaseError("lease role or authoritative identity is invalid")
        expected = ROLE_IDENTITIES.get(self.role_id)
        identity_matches = self.authoritative_identity == expected
        if self.role_id == "specialist_reviewer":
            identity_matches = identity_matches or self.authoritative_identity.startswith(
                "specialist_reviewer_service_"
            )
        if expected is None or not identity_matches:
            raise LeaseError("lease role or authoritative identity is invalid")
        if not isinstance(self.expires_at, datetime) or self.expires_at.tzinfo is None or self.expires_at.utcoffset() is None:
            raise LeaseError("lease expiry must be timezone-aware")
        if not isinstance(self.revoked, bool):
            raise LeaseError("lease revocation flag must be boolean")

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

    def __post_init__(self) -> None:
        if (
            not isinstance(self.factory_id, str)
            or not isinstance(self.task_id, str)
            or not SAFE_IDENTIFIER.fullmatch(self.factory_id)
            or not SAFE_IDENTIFIER.fullmatch(self.task_id)
        ):
            raise StateError("factory and task ids must be safe nonempty identifiers")
        if self.state not in ALLOWED_TRANSITIONS:
            raise InvalidTransition(f"unknown task state: {self.state}")
        if isinstance(self.version, bool) or not isinstance(self.version, int) or self.version < 0:
            raise StaleVersion("state version must be a nonnegative integer")
        if not isinstance(self.updated_at, datetime) or self.updated_at.tzinfo is None or self.updated_at.utcoffset() is None:
            raise StateError("state update timestamp must be timezone-aware")
        if self.updated_by not in {CONTROLLER_IDENTITY, OWNER_IDENTITY}:
            raise AuthorityError("state updater must be the controller or Tim")
        leases = tuple(deepcopy(self.leases))
        if len({lease.lease_id for lease in leases}) != len(leases):
            raise LeaseError("task state contains duplicate lease ids")
        consumed = frozenset(self.consumed_evidence_ids)
        if any(not isinstance(item, str) or not SAFE_IDENTIFIER.fullmatch(item) for item in consumed):
            raise EvidenceError("consumed evidence history contains an invalid id")
        remediation = deepcopy(self.remediation)
        stall = deepcopy(self.stall)
        if self.state == "REMEDIATION":
            required = {"return_state", "required_actions", "failure_code"}
            if (
                not isinstance(remediation, dict)
                or set(remediation) != required
                or not isinstance(remediation.get("required_actions"), list)
                or not remediation["required_actions"]
                or remediation.get("return_state") not in REMEDIATION_RETURN_STATES
                or any(not isinstance(item, str) or not item.strip() for item in remediation["required_actions"])
                or not isinstance(remediation.get("failure_code"), str)
                or not remediation["failure_code"].strip()
            ):
                raise InvalidTransition("REMEDIATION state requires deterministic return fields")
        elif remediation is not None:
            raise InvalidTransition("remediation fields are valid only in REMEDIATION")
        if self.state == "STALLED":
            required = {"reason_code", "resume_condition", "owner_action_required"}
            if (
                not isinstance(stall, dict)
                or set(stall) != required
                or not isinstance(stall.get("reason_code"), str)
                or not stall["reason_code"].strip()
                or not isinstance(stall.get("resume_condition"), str)
                or not stall["resume_condition"].strip()
                or not isinstance(stall.get("owner_action_required"), bool)
            ):
                raise InvalidTransition("STALLED state requires deterministic resume fields")
        elif stall is not None:
            raise InvalidTransition("stall fields are valid only in STALLED")
        object.__setattr__(self, "leases", leases)
        object.__setattr__(self, "consumed_evidence_ids", consumed)
        object.__setattr__(self, "remediation", remediation)
        object.__setattr__(self, "stall", stall)


class FactoryStateMachine:
    def __init__(self, initial: TaskState):
        if initial.state not in ALLOWED_TRANSITIONS:
            raise InvalidTransition(f"unknown initial state: {initial.state}")
        if initial.version < 0:
            raise StaleVersion("state version cannot be negative")
        self._state = deepcopy(initial)
        self._audit: list[dict[str, Any]] = []

    @property
    def state(self) -> TaskState:
        return deepcopy(self._state)

    @property
    def audit(self) -> tuple[dict[str, Any], ...]:
        return tuple(deepcopy(self._audit))

    @property
    def last_audit_event(self) -> dict[str, Any] | None:
        return deepcopy(self._audit[-1]) if self._audit else None

    @staticmethod
    def _require_controller(caller_identity: str) -> None:
        if caller_identity != CONTROLLER_IDENTITY:
            raise AuthorityError("only the authoritative controller may mutate state")

    @staticmethod
    def _require_owner(caller_identity: str) -> None:
        if caller_identity != OWNER_IDENTITY:
            raise AuthorityError("only Tim, the Factory Owner, may issue an owner override")

    def issue_lease(
        self,
        caller_identity: str,
        lease: Lease,
        *,
        expected_version: int,
        now: datetime | None = None,
    ) -> TaskState:
        self._require_controller(caller_identity)
        self._require_version(expected_version)
        now = now or datetime.now(timezone.utc)
        if self._state.state == "PAUSED":
            raise LeaseError("cannot issue leases while PAUSED")
        if not SAFE_IDENTIFIER.fullmatch(lease.lease_id):
            raise LeaseError("lease id is invalid")
        if lease.role_id not in ROLE_IDENTITIES:
            raise LeaseError("unknown delegated role")
        if not self._identity_matches_role(lease.role_id, lease.authoritative_identity):
            raise LeaseError("lease identity does not match the delegated role")
        if self._state.state not in ROLE_ALLOWED_STATES[lease.role_id]:
            raise LeaseError("role is not authorized in the current state")
        if lease.expires_at.tzinfo is None or lease.expires_at.utcoffset() is None:
            raise LeaseError("lease expiry must be timezone-aware")
        if not lease.active_at(now):
            raise LeaseError("cannot issue an expired or revoked lease")
        if any(item.lease_id == lease.lease_id for item in self._state.leases):
            raise LeaseError("lease id replay")
        if any(item.role_id == lease.role_id and item.active_at(now) for item in self._state.leases):
            raise LeaseError("role already has an active lease for this task")
        return self._commit(
            replace(self._state, leases=self._state.leases + (lease,)),
            "LEASE_ISSUED",
            caller_identity,
            details={
                "lease_id": lease.lease_id,
                "role_id": lease.role_id,
                "expires_at": lease.expires_at.isoformat(),
            },
        )

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
        self._require_transition_evidence(target, checked)
        if target == "REMEDIATION":
            required = {"return_state", "required_actions", "failure_code"}
            if (
                not remediation
                or set(remediation) != required
                or not remediation["required_actions"]
                or remediation["return_state"] not in REMEDIATION_RETURN_STATES
            ):
                raise InvalidTransition("REMEDIATION requires deterministic return fields")
        if target == "STALLED":
            required = {"reason_code", "resume_condition", "owner_action_required"}
            if not stall or not required.issubset(stall):
                raise InvalidTransition("STALLED requires deterministic resume fields")
        leases = tuple(replace(lease, revoked=True) for lease in self._state.leases)
        consumed = self._state.consumed_evidence_ids | {item.evidence_id for item in checked}
        updated = replace(
            self._state,
            state=target,
            leases=leases,
            consumed_evidence_ids=frozenset(consumed),
            remediation=remediation if target == "REMEDIATION" else None,
            stall=stall if target == "STALLED" else None,
        )
        return self._commit(
            updated,
            "STATE_TRANSITION",
            caller_identity,
            details={"evidence_ids": sorted(item.evidence_id for item in checked)},
        )

    def owner_override(
        self,
        caller_identity: str,
        target: str,
        *,
        expected_version: int,
        reason: str,
        remediation: dict[str, Any] | None = None,
        stall: dict[str, Any] | None = None,
    ) -> TaskState:
        """Apply Tim's unilateral, audited override without an approval gate."""

        self._require_owner(caller_identity)
        self._require_version(expected_version)
        if target not in ALLOWED_TRANSITIONS:
            raise InvalidTransition(f"unknown target state: {target}")
        if not reason.strip():
            raise InvalidTransition("owner override requires an audit reason")
        if target == "REMEDIATION":
            required = {"return_state", "required_actions", "failure_code"}
            if (
                not remediation
                or set(remediation) != required
                or not remediation["required_actions"]
                or remediation["return_state"] not in REMEDIATION_RETURN_STATES
            ):
                raise InvalidTransition("REMEDIATION requires deterministic return fields")
        if target == "STALLED":
            required = {"reason_code", "resume_condition", "owner_action_required"}
            if not stall or not required.issubset(stall):
                raise InvalidTransition("STALLED requires deterministic resume fields")
        leases = tuple(replace(lease, revoked=True) for lease in self._state.leases)
        updated = replace(
            self._state,
            state=target,
            leases=leases,
            remediation=remediation if target == "REMEDIATION" else None,
            stall=stall if target == "STALLED" else None,
        )
        return self._commit(
            updated,
            "OWNER_OVERRIDE",
            caller_identity,
            details={"reason": reason},
        )

    def assert_dispatch_allowed(self, caller_identity: str, lease_id: str, *, now: datetime | None = None) -> None:
        if caller_identity not in {CONTROLLER_IDENTITY, OWNER_IDENTITY}:
            raise AuthorityError("dispatch is limited to the controller or Tim, the Factory Owner")
        now = now or datetime.now(timezone.utc)
        if self._state.state == "PAUSED":
            raise AuthorityError("dispatch is blocked while PAUSED")
        if caller_identity == OWNER_IDENTITY:
            return
        lease = next((item for item in self._state.leases if item.lease_id == lease_id), None)
        if lease is None or not lease.active_at(now):
            raise LeaseError("dispatch requires an active lease")
        if lease.role_id not in ROLE_ALLOWED_STATES:
            raise LeaseError("dispatch lease role is unknown")
        if not self._identity_matches_role(lease.role_id, lease.authoritative_identity):
            raise LeaseError("dispatch lease identity is invalid")
        if self._state.state not in ROLE_ALLOWED_STATES[lease.role_id]:
            raise LeaseError("dispatch lease role is not authorized in the current state")

    def _require_version(self, expected: int) -> None:
        if self._state.version != expected:
            raise StaleVersion(f"expected version {expected}, current version {self._state.version}")

    def _verify_evidence(self, evidence: tuple[Evidence, ...], now: datetime) -> None:
        leases = {item.lease_id: item for item in self._state.leases}
        evidence_ids: set[str] = set()
        for item in evidence:
            if not isinstance(item.evidence_id, str) or not SAFE_IDENTIFIER.fullmatch(item.evidence_id):
                raise EvidenceError("evidence id is invalid")
            if item.evidence_id in evidence_ids:
                raise EvidenceError("duplicate evidence id in transition")
            evidence_ids.add(item.evidence_id)
            if item.evidence_id in self._state.consumed_evidence_ids:
                raise EvidenceError("evidence replay")
            if item.task_id != self._state.task_id or item.signature_valid is not True:
                raise EvidenceError("evidence provenance invalid")
            if item.created_at.tzinfo is None or item.created_at.utcoffset() is None:
                raise EvidenceError("evidence timestamp must be timezone-aware")
            if item.created_at > now:
                raise EvidenceError("future-dated evidence is invalid")
            if not COMMIT_SHA.fullmatch(item.source_commit):
                raise EvidenceError("evidence source commit is invalid")
            if not SHA256_DIGEST.fullmatch(item.artifact_digest):
                raise EvidenceError("evidence artifact digest is invalid")
            if item.producer_role not in ROLE_IDENTITIES:
                raise EvidenceError("evidence producer role is unknown")
            if self._state.state not in ROLE_ALLOWED_STATES[item.producer_role]:
                raise EvidenceError("evidence producer role is not authorized in the current state")
            if not self._identity_matches_role(item.producer_role, item.producer_identity):
                raise EvidenceError("evidence producer identity is invalid")
            lease = leases.get(item.lease_id)
            if lease is None or not lease.active_at(now):
                raise EvidenceError("evidence lease expired or revoked")
            if lease.authoritative_identity != item.producer_identity or lease.role_id != item.producer_role:
                raise EvidenceError("evidence identity is not bound to lease")
            if item.reviewer_identity is not None and item.reviewer_identity == item.producer_identity:
                raise EvidenceError("self approval denied")
            if item.reviewer_identity is not None and not self._is_known_identity(item.reviewer_identity):
                raise EvidenceError("evidence reviewer identity is unknown")

    def _require_transition_evidence(self, target: str, evidence: tuple[Evidence, ...]) -> None:
        required_roles = REQUIRED_EVIDENCE_ROLES.get((self._state.state, target), set())
        producer_roles = {item.producer_role for item in evidence}
        missing = required_roles - producer_roles
        if missing:
            raise EvidenceError(
                "transition requires evidence from: " + ", ".join(sorted(missing))
            )
        if (
            self._state.state == "REMEDIATION"
            and target not in {"PAUSED", "STALLED"}
            and not evidence
        ):
            raise EvidenceError("leaving REMEDIATION requires provenance-bound evidence")
        if (
            self._state.state == "REMEDIATION"
            and target not in {"PAUSED", "STALLED"}
            and self._state.remediation is not None
            and target != self._state.remediation["return_state"]
        ):
            raise InvalidTransition("REMEDIATION may return only to its recorded return state")

    @staticmethod
    def _identity_matches_role(role_id: str, identity: str) -> bool:
        expected = ROLE_IDENTITIES.get(role_id)
        if expected is None:
            return False
        if role_id == "specialist_reviewer":
            return identity == expected or identity.startswith("specialist_reviewer_service_")
        return identity == expected

    @staticmethod
    def _is_known_identity(identity: str) -> bool:
        return (
            identity in {CONTROLLER_IDENTITY, OWNER_IDENTITY, *ROLE_IDENTITIES.values()}
            or identity.startswith("specialist_reviewer_service_")
        )

    def _commit(
        self,
        updated: TaskState,
        event_type: str,
        caller_identity: str,
        *,
        details: dict[str, Any] | None = None,
    ) -> TaskState:
        now = datetime.now(timezone.utc)
        updated = replace(
            updated,
            version=self._state.version + 1,
            updated_at=now,
            updated_by=caller_identity,
        )
        event = {
            "event_type": event_type,
            "task_id": updated.task_id,
            "from_version": self._state.version,
            "to_version": updated.version,
            "state": updated.state,
            "actor_identity": caller_identity,
            "at": now.isoformat(),
        }
        if details:
            event["details"] = details
        self._audit.append(deepcopy(event))
        self._state = deepcopy(updated)
        return deepcopy(updated)
