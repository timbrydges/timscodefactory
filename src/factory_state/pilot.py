"""Fail-closed activation policy for the staged three-system pilot."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping


OWNER_IDENTITY = "tim_brydges"
PILOT_SYSTEMS = frozenset({"planner", "builder", "inspector"})
REQUIRED_ACTIVATION_GATES = (
    "pilot_contract_approved",
    "acceptance_contract_approved",
    "aws_account_verified",
    "private_repository_controls_verified",
    "planner_identity_deployed_verified",
    "builder_identity_deployed_verified",
    "inspector_identity_deployed_verified",
    "controller_deployed_verified",
    "state_store_deployed_verified",
    "oidc_trust_verified",
    "release_storage_verified",
    "rollback_drill_verified",
)
DRY_RUN_ALLOWLIST = frozenset(
    {
        "contract_validation",
        "threat_modeling",
        "identity_policy_validation",
        "mocked_state_transition",
        "local_test_execution",
        "deterministic_build_without_release",
    }
)
FORBIDDEN_UNTIL_INFRA_VERIFICATION = frozenset(
    {
        "aws_resource_write",
        "production_environment_entry",
        "rollback_drill",
    }
)
FORBIDDEN_UNTIL_LIVE = frozenset(
    {
        "operational_role_dispatch",
        "pilot_repository_write",
        "live_state_transition",
        "real_release",
    }
)


class PilotGateError(RuntimeError):
    """The requested pilot operation is not authorized by verified readiness."""


@dataclass(frozen=True)
class PilotActivationPolicy:
    """Runtime view of the owner-approved pilot activation contract."""

    phase: str
    permissions: Mapping[str, str]
    gates: Mapping[str, bool]
    dry_run_allowlist: frozenset[str]
    forbidden_until_infra_verification: frozenset[str]
    forbidden_until_live: frozenset[str]

    @classmethod
    def from_contract(cls, contract: Mapping[str, Any]) -> "PilotActivationPolicy":
        execution = contract.get("execution")
        activation = contract.get("activation")
        if not isinstance(execution, Mapping) or not isinstance(activation, Mapping):
            raise PilotGateError("pilot execution or activation policy is missing")

        raw_gates = activation.get("gates")
        if not isinstance(raw_gates, Mapping):
            raise PilotGateError("pilot activation gates are missing")
        gates: dict[str, bool] = {}
        for name, value in raw_gates.items():
            if not isinstance(name, str) or not isinstance(value, Mapping):
                raise PilotGateError("pilot activation gate is malformed")
            verified = value.get("verified")
            if not isinstance(verified, bool):
                raise PilotGateError(f"pilot activation gate {name} lacks a boolean verdict")
            gates[name] = verified

        required = activation.get("required_gates")
        if not isinstance(required, list) or tuple(required) != REQUIRED_ACTIVATION_GATES:
            raise PilotGateError("pilot activation gate set or order is not authoritative")
        if set(gates) != set(REQUIRED_ACTIVATION_GATES):
            raise PilotGateError("pilot activation gate verdicts are incomplete or unknown")

        permissions = {
            key: execution.get(key)
            for key in (
                "dry_run_simulation",
                "infrastructure_provisioning",
                "rollback_drill",
                "operational_role_activation",
                "pilot_repository_writes",
                "live_task_transitions",
                "real_release",
            )
        }
        if any(value not in {"ALLOW", "DENY"} for value in permissions.values()):
            raise PilotGateError("pilot execution permissions must explicitly ALLOW or DENY")

        policy = cls(
            phase=str(execution.get("phase")),
            permissions=permissions,
            gates=gates,
            dry_run_allowlist=frozenset(activation.get("dry_run_allowlist", [])),
            forbidden_until_infra_verification=frozenset(
                activation.get("forbidden_until_infra_verification", [])
            ),
            forbidden_until_live=frozenset(activation.get("forbidden_until_live", [])),
        )
        policy.assert_invariants()
        return policy

    @property
    def readiness_verified(self) -> bool:
        return all(self.gates.get(name) is True for name in REQUIRED_ACTIVATION_GATES)

    @property
    def live_pilot(self) -> bool:
        return self.phase == "LIVE_PILOT" and self.readiness_verified

    def assert_invariants(self) -> None:
        if self.phase not in {"DRY_RUN_ONLY", "INFRA_VERIFICATION", "LIVE_PILOT", "COMPLETE"}:
            raise PilotGateError("pilot phase is unknown")
        if self.dry_run_allowlist != DRY_RUN_ALLOWLIST:
            raise PilotGateError("pilot dry-run allowlist drifted")
        if self.forbidden_until_infra_verification != FORBIDDEN_UNTIL_INFRA_VERIFICATION:
            raise PilotGateError("pilot pre-infrastructure denylist drifted")
        if self.forbidden_until_live != FORBIDDEN_UNTIL_LIVE:
            raise PilotGateError("pilot pre-activation denylist drifted")
        if self.phase == "DRY_RUN_ONLY":
            expected = {
                "dry_run_simulation": "ALLOW",
                "infrastructure_provisioning": "DENY",
                "rollback_drill": "DENY",
                "operational_role_activation": "DENY",
                "pilot_repository_writes": "DENY",
                "live_task_transitions": "DENY",
                "real_release": "DENY",
            }
            if dict(self.permissions) != expected:
                raise PilotGateError("dry-run phase must deny every operational capability")
        elif self.phase == "INFRA_VERIFICATION":
            expected = {
                "dry_run_simulation": "ALLOW",
                "infrastructure_provisioning": "ALLOW",
                "rollback_drill": "ALLOW",
                "operational_role_activation": "DENY",
                "pilot_repository_writes": "DENY",
                "live_task_transitions": "DENY",
                "real_release": "DENY",
            }
            if dict(self.permissions) != expected:
                raise PilotGateError("infrastructure verification must keep roles and real release denied")
            for gate in ("pilot_contract_approved", "acceptance_contract_approved", "aws_account_verified"):
                if self.gates.get(gate) is not True:
                    raise PilotGateError(f"INFRA_VERIFICATION requires gate: {gate}")
        elif self.phase == "LIVE_PILOT":
            if not self.readiness_verified:
                raise PilotGateError("LIVE_PILOT requires every readiness gate")
            if any(self.permissions.get(name) != "ALLOW" for name in self.permissions):
                raise PilotGateError("LIVE_PILOT permissions must be explicitly enabled")

    def assert_dry_run_allowed(self, operation: str) -> None:
        if self.permissions.get("dry_run_simulation") != "ALLOW":
            raise PilotGateError("dry-run simulation is disabled")
        if operation not in self.dry_run_allowlist:
            raise PilotGateError(f"operation is not on the dry-run allowlist: {operation}")

    def assert_role_activation_allowed(self, system: str) -> None:
        if system not in PILOT_SYSTEMS:
            raise PilotGateError(f"unknown pilot system: {system}")
        if not self.live_pilot:
            raise PilotGateError("operational roles require LIVE_PILOT and every verified readiness gate")
        if self.permissions.get("operational_role_activation") != "ALLOW":
            raise PilotGateError("operational role activation is denied")

    def assert_infrastructure_provisioning_allowed(self, *, actor_identity: str) -> None:
        if actor_identity != OWNER_IDENTITY:
            raise PilotGateError("only Tim may authorize pilot infrastructure provisioning")
        if self.phase not in {"INFRA_VERIFICATION", "LIVE_PILOT"}:
            raise PilotGateError("infrastructure provisioning requires INFRA_VERIFICATION")
        if self.permissions.get("infrastructure_provisioning") != "ALLOW":
            raise PilotGateError("infrastructure provisioning is denied")

    def assert_rollback_drill_allowed(self, *, actor_identity: str) -> None:
        self.assert_infrastructure_provisioning_allowed(actor_identity=actor_identity)
        for gate in ("oidc_trust_verified", "state_store_deployed_verified", "release_storage_verified"):
            if self.gates.get(gate) is not True:
                raise PilotGateError(f"rollback drill requires gate: {gate}")
        if self.permissions.get("rollback_drill") != "ALLOW":
            raise PilotGateError("rollback drill is denied")

    def assert_repository_write_allowed(self) -> None:
        if not self.live_pilot or self.permissions.get("pilot_repository_writes") != "ALLOW":
            raise PilotGateError("pilot repository writes require verified LIVE_PILOT activation")

    def assert_live_transition_allowed(self) -> None:
        if not self.live_pilot or self.permissions.get("live_task_transitions") != "ALLOW":
            raise PilotGateError("live task transitions require verified LIVE_PILOT activation")

    def assert_merge_allowed(
        self,
        *,
        inspector_evidence_verified: bool,
        deterministic_ci_passed: bool,
        exact_commit_binding_verified: bool,
    ) -> None:
        if not self.live_pilot:
            raise PilotGateError("merge eligibility requires verified LIVE_PILOT activation")
        if not all(
            (
                inspector_evidence_verified,
                deterministic_ci_passed,
                exact_commit_binding_verified,
            )
        ):
            raise PilotGateError("merge requires Inspector evidence, green CI, and exact commit binding")

    def assert_real_release_allowed(
        self,
        *,
        actor_identity: str,
        inspector_evidence_verified: bool,
        deterministic_ci_passed: bool,
        exact_commit_binding_verified: bool,
    ) -> None:
        if actor_identity != OWNER_IDENTITY:
            raise PilotGateError("only Tim may authorize a real pilot release")
        if not self.live_pilot or self.permissions.get("real_release") != "ALLOW":
            raise PilotGateError("real release requires verified LIVE_PILOT activation")
        self.assert_merge_allowed(
            inspector_evidence_verified=inspector_evidence_verified,
            deterministic_ci_passed=deterministic_ci_passed,
            exact_commit_binding_verified=exact_commit_binding_verified,
        )
