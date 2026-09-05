#!/usr/bin/env python3
"""Validate and simulate the staged three-system pilot activation contract."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

import jsonschema
import yaml


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from factory_state.pilot import (  # noqa: E402
    DRY_RUN_ALLOWLIST,
    FORBIDDEN_UNTIL_INFRA_VERIFICATION,
    FORBIDDEN_UNTIL_LIVE,
    OWNER_IDENTITY,
    PILOT_SYSTEMS,
    REQUIRED_ACTIVATION_GATES,
    PilotActivationPolicy,
    PilotGateError,
)


EXPECTED_SYSTEM_BINDINGS = {
    "planner": {
        "factory_role": "software_architect",
        "authoritative_identity": "software_architect_service",
        "provider_profile": "reasoning_architect",
    },
    "builder": {
        "factory_role": "engineering_agent",
        "authoritative_identity": "engineering_agent_service",
        "provider_profile": "coding_primary",
    },
    "inspector": {
        "factory_role": "independent_inspector",
        "authoritative_identity": "independent_inspector_service",
        "provider_profile": "review_adversarial",
    },
}


def load_contract(root: Path = ROOT) -> dict[str, Any]:
    path = root / "factory/pilot/operating-contract.yaml"
    value = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise PilotGateError("pilot operating contract must be a YAML mapping")
    return value


def validate_contract(contract: dict[str, Any], root: Path = ROOT) -> tuple[str, ...]:
    errors: list[str] = []
    try:
        schema = json.loads(
            (root / "factory/schemas/pilot-operating-contract.schema.json").read_text(
                encoding="utf-8"
            )
        )
        jsonschema.Draft202012Validator.check_schema(schema)
        jsonschema.Draft202012Validator(schema, format_checker=jsonschema.FormatChecker()).validate(contract)
    except Exception as exc:
        return (f"pilot contract schema validation failed: {exc}",)

    if contract.get("approval") != {
        "owner_identity": OWNER_IDENTITY,
        "authority": "factory_owner",
        "approved_on": "2026-09-05",
        "approval_required_from_others": False,
    }:
        errors.append("pilot contract must be approved only by Tim as Factory Owner")

    repository = contract.get("pilot", {}).get("repository", {})
    if repository.get("full_name") != "timbrydges/tims-factory-pilot":
        errors.append("pilot must bind the single approved private repository")
    if repository.get("visibility") != "private" or repository.get("maximum_repository_count") != 1:
        errors.append("pilot repository scope must be exactly one private repository")

    feature = contract.get("pilot", {}).get("feature_slice", {})
    if feature.get("name") != "deterministic_release_readiness_checklist":
        errors.append("pilot feature slice is not the owner-approved bounded checklist")

    systems = contract.get("systems", {})
    for system, expected in EXPECTED_SYSTEM_BINDINGS.items():
        actual = systems.get(system, {})
        if any(actual.get(key) != value for key, value in expected.items()):
            errors.append(f"{system} does not match its approved Factory role and identity")
    identities = [systems.get(name, {}).get("authoritative_identity") for name in sorted(PILOT_SYSTEMS)]
    if len(set(identities)) != 3:
        errors.append("Planner, Builder, and Inspector identities must be distinct")

    activation = contract.get("activation", {})
    if activation.get("default") != "DENY":
        errors.append("pilot activation must default deny")
    if tuple(activation.get("required_gates", [])) != REQUIRED_ACTIVATION_GATES:
        errors.append("pilot activation gate list is incomplete or reordered")
    if frozenset(activation.get("dry_run_allowlist", [])) != DRY_RUN_ALLOWLIST:
        errors.append("pilot dry-run allowlist drifted")
    if frozenset(activation.get("forbidden_until_infra_verification", [])) != FORBIDDEN_UNTIL_INFRA_VERIFICATION:
        errors.append("pilot pre-infrastructure denylist drifted")
    if frozenset(activation.get("forbidden_until_live", [])) != FORBIDDEN_UNTIL_LIVE:
        errors.append("pilot pre-activation denylist drifted")
    gates = activation.get("gates", {})
    if set(gates) == set(REQUIRED_ACTIVATION_GATES):
        for gate_name, gate in gates.items():
            verified = gate.get("verified")
            evidence = gate.get("evidence")
            if verified is True and not evidence:
                errors.append(f"verified activation gate lacks evidence: {gate_name}")
            if verified is False and evidence:
                errors.append(f"unverified activation gate claims evidence: {gate_name}")

    try:
        PilotActivationPolicy.from_contract(contract)
    except PilotGateError as exc:
        errors.append(str(exc))

    merge = contract.get("merge_gate", {})
    if not all(
        merge.get(name) is True
        for name in (
            "inspector_evidence_required",
            "deterministic_ci_required",
            "exact_commit_binding_required",
            "owner_override_preserved",
            "override_disqualifies_pilot_success",
        )
    ):
        errors.append("pilot merge contract must require Inspector, CI, and exact commit evidence")

    release = contract.get("release", {})
    if release.get("authority_identity") != OWNER_IDENTITY or release.get("other_release_authorities") != []:
        errors.append("Tim must be the only real pilot release authority")
    if release.get("rollback_drill_before_first_real_release") is not True:
        errors.append("rollback drill must precede the first real pilot release")
    if release.get("aws_provisioning_order") != [
        "oidc_trust",
        "state_and_release_storage",
        "rollback_drill",
    ]:
        errors.append("AWS pilot provisioning order must be OIDC, storage/state, then rollback drill")

    limits = contract.get("limits", {})
    if not (
        limits.get("currency") == "USD"
        and limits.get("warning_spend") == 5.0
        and limits.get("hard_stop_spend") == 10.0
        and limits.get("automated_wall_clock_hours") == 24
        and limits.get("elapsed_business_days") == 5
        and limits.get("maximum_remediation_cycles") == 2
    ):
        errors.append("pilot spend, time, or remediation limits differ from the approved contract")

    prohibited = " ".join(contract.get("prohibited_data", [])).lower()
    for required_term in ("credential", "personal", "suncor", "proprietary", "external content"):
        if required_term not in prohibited:
            errors.append(f"pilot prohibited-data contract is missing: {required_term}")

    acceptance = contract.get("acceptance_tests", [])
    if [item.get("id") for item in acceptance] != [f"AT-{index:02d}" for index in range(1, 9)]:
        errors.append("pilot acceptance tests must be the complete ordered AT-01 through AT-08 set")

    threats = contract.get("threat_controls", {})
    if threats != {
        "untrusted_input_is_data_only": True,
        "sanitization_gate": True,
        "monitoring_required": True,
        "kill_switch_owner": OWNER_IDENTITY,
        "high_risk_change_response": "PAUSE_AND_REQUIRE_NEW_OWNER_APPROVED_CONTRACT",
    }:
        errors.append("pilot threat controls must preserve sanitization, monitoring, and Tim's kill switch")

    escalation = contract.get("aws_escalation", {})
    if escalation.get("blocked_since") != "2026-08-25":
        errors.append("AWS escalation must retain the first observed blocker date")
    if escalation.get("checkpoint_business_days") != [7, 10]:
        errors.append("AWS escalation checkpoint must remain 7-10 business days")
    if escalation.get("escalation_deadline") != "2026-09-09":
        errors.append("AWS escalation deadline must remain explicit")

    status = contract.get("status")
    phase = contract.get("execution", {}).get("phase")
    expected_status = {
        "DRY_RUN_ONLY": "OWNER_APPROVED_DRY_RUN_ONLY",
        "INFRA_VERIFICATION": "OWNER_APPROVED_INFRA_VERIFICATION",
        "LIVE_PILOT": "OWNER_APPROVED_LIVE_PILOT",
    }.get(phase)
    if expected_status is not None and status != expected_status:
        errors.append("pilot contract status must match its execution phase")

    return tuple(errors)


def simulate_current_policy(contract: dict[str, Any]) -> tuple[str, ...]:
    """Exercise the real gate object without AWS, credentials, or repository writes."""

    errors: list[str] = []
    try:
        policy = PilotActivationPolicy.from_contract(contract)
    except PilotGateError as exc:
        return (f"cannot simulate invalid pilot policy: {exc}",)

    for operation in sorted(DRY_RUN_ALLOWLIST):
        try:
            policy.assert_dry_run_allowed(operation)
        except PilotGateError as exc:
            errors.append(f"approved dry-run operation rejected ({operation}): {exc}")

    try:
        policy.assert_dry_run_allowed("real_release")
        errors.append("real release was accepted as a dry-run operation")
    except PilotGateError:
        pass

    if policy.phase == "DRY_RUN_ONLY":
        for system in sorted(PILOT_SYSTEMS):
            try:
                policy.assert_role_activation_allowed(system)
                errors.append(f"{system} activated during DRY_RUN_ONLY")
            except PilotGateError:
                pass
        for check, operation in (
            (policy.assert_repository_write_allowed, "pilot repository write"),
            (policy.assert_live_transition_allowed, "live task transition"),
        ):
            try:
                check()
                errors.append(f"{operation} was allowed during DRY_RUN_ONLY")
            except PilotGateError:
                pass
        for check, operation in (
            (
                lambda: policy.assert_infrastructure_provisioning_allowed(
                    actor_identity=OWNER_IDENTITY
                ),
                "infrastructure provisioning",
            ),
            (
                lambda: policy.assert_rollback_drill_allowed(actor_identity=OWNER_IDENTITY),
                "rollback drill",
            ),
        ):
            try:
                check()
                errors.append(f"{operation} was allowed during DRY_RUN_ONLY")
            except PilotGateError:
                pass
        try:
            policy.assert_real_release_allowed(
                actor_identity=OWNER_IDENTITY,
                inspector_evidence_verified=True,
                deterministic_ci_passed=True,
                exact_commit_binding_verified=True,
            )
            errors.append("real release was allowed during DRY_RUN_ONLY")
        except PilotGateError:
            pass
    elif policy.phase == "INFRA_VERIFICATION":
        try:
            policy.assert_infrastructure_provisioning_allowed(actor_identity=OWNER_IDENTITY)
        except PilotGateError as exc:
            errors.append(f"owner infrastructure verification was rejected: {exc}")
        for system in sorted(PILOT_SYSTEMS):
            try:
                policy.assert_role_activation_allowed(system)
                errors.append(f"{system} activated during INFRA_VERIFICATION")
            except PilotGateError:
                pass
    elif policy.phase == "LIVE_PILOT":
        for system in sorted(PILOT_SYSTEMS):
            try:
                policy.assert_role_activation_allowed(system)
            except PilotGateError as exc:
                errors.append(f"verified live role rejected ({system}): {exc}")

    return tuple(errors)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--mode", choices=["validate", "simulate"], default="validate")
    args = parser.parse_args()

    try:
        contract = load_contract(args.root)
        errors = (
            validate_contract(contract, args.root)
            if args.mode == "validate"
            else simulate_current_policy(contract)
        )
    except Exception as exc:
        errors = (f"pilot gate failed closed: {exc}",)

    if errors:
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
        return 1
    print(f"Pilot {args.mode} passed ({contract['execution']['phase']})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
