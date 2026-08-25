#!/usr/bin/env python3
"""Execute static, adversarial, recovery, and live F3.1 preflight checks."""

from __future__ import annotations

import argparse
import base64
import copy
import json
import os
import sys
import tempfile
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path

import yaml

try:
    from scripts.build_manifest import render_manifest
    from scripts.validate_registry import load_yaml, validate
except ModuleNotFoundError:  # direct `python scripts/preflight.py`
    from build_manifest import render_manifest
    from validate_registry import load_yaml, validate


ROOT = Path(__file__).resolve().parents[1]
EXPECTED_OIDC_PREFIX = "repo:timbrydges@214414801/timscodefactory@1345656137"
sys.path.insert(0, str(ROOT / "src"))

try:
    from scripts.release_control import (
        Deployment,
        ReleaseControlError,
        prepare_rollback_transaction,
        validate_s3_head,
    )
    from scripts.validate_workflows import validate as validate_workflows
except ModuleNotFoundError:  # direct `python scripts/preflight.py`
    from release_control import (
        Deployment,
        ReleaseControlError,
        prepare_rollback_transaction,
        validate_s3_head,
    )
    from validate_workflows import validate as validate_workflows

from factory_state.model import (  # noqa: E402
    AuthorityError,
    Evidence,
    EvidenceError,
    FactoryStateMachine,
    Lease,
    LeaseError,
    TaskState,
)


def _copy_control_plane(destination: Path) -> None:
    import shutil

    shutil.copytree(ROOT / "factory", destination / "factory")
    shutil.copytree(ROOT / "config", destination / "config")
    shutil.copytree(ROOT / "scripts", destination / "scripts")
    for filename in ("requirements-dev.txt", "pyproject.toml", "README.md"):
        shutil.copy2(ROOT / filename, destination / filename)
    (destination / "MANIFEST.sha256").write_text(render_manifest(destination), encoding="utf-8")


def _mutation_fails(mutator) -> bool:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        _copy_control_plane(root)
        mutator(root)
        return not validate(root, check_manifest=False).ok


def static_checks() -> dict[str, bool]:
    registry = load_yaml(ROOT / "factory/registry.yaml")
    result = validate(ROOT)
    return {
        "PF-01": result.ok,
        "PF-02": (ROOT / "MANIFEST.sha256").exists() and (ROOT / "MANIFEST.sha256").read_text(encoding="utf-8") == render_manifest(ROOT),
        "PF-03": (
            registry["repository"]["full_name"] == "timbrydges/timscodefactory"
            and registry["repository"]["visibility"] == "public"
        ),
        "PF-04": result.ok,
        "PF-18": (
            registry["release"]["environment"] == "production"
            and registry["owner_authority"]["ultimate_authority"] is True
            and registry["owner_authority"]["approval_required"] is False
            and registry["owner_authority"]["may_approve_own_changes"] is True
            and registry["owner_authority"]["may_bypass_all_gates"] is True
        ),
    }


def adversarial_checks() -> dict[str, bool]:
    def unknown_role(root: Path):
        p = root / "factory/roles/engineering_agent.yaml"
        d = load_yaml(p); d["role_id"] = "rogue_admin"; p.write_text(yaml.safe_dump(d, sort_keys=False), encoding="utf-8")

    def missing_profile(root: Path):
        p = root / "factory/roles/engineering_agent.yaml"
        d = load_yaml(p); d["credential_profile"] = "god_mode"; p.write_text(yaml.safe_dump(d, sort_keys=False), encoding="utf-8")

    def provider_collision(root: Path):
        p = root / "factory/profiles/providers.yaml"
        d = load_yaml(p); d["profiles"]["review_adversarial"]["provider_family"] = "openai"; p.write_text(yaml.safe_dump(d, sort_keys=False), encoding="utf-8")

    def protected_write(root: Path):
        p = root / "factory/roles/engineering_agent.yaml"
        d = load_yaml(p); d["writable_paths"].append("factory/**"); p.write_text(yaml.safe_dump(d, sort_keys=False), encoding="utf-8")

    def unauthorized_dispatch(root: Path):
        p = root / "factory/roles/engineering_agent.yaml"
        d = load_yaml(p); d["gate_authority"]["may_dispatch"] = True; p.write_text(yaml.safe_dump(d, sort_keys=False), encoding="utf-8")

    def oidc_tamper(root: Path):
        p = root / "factory/profiles/credentials.yaml"
        d = load_yaml(p); d["profiles"]["release_oidc_workflow"]["cloud_subject"] = "repo:*:*"; p.write_text(yaml.safe_dump(d, sort_keys=False), encoding="utf-8")

    def registry_tamper(root: Path):
        p = root / "factory/registry.yaml"
        d = load_yaml(p); d["repository"]["full_name"] = "attacker/redirected"; p.write_text(yaml.safe_dump(d, sort_keys=False), encoding="utf-8")

    return {
        "PF-05": _mutation_fails(unknown_role),
        "PF-06": _mutation_fails(missing_profile),
        "PF-07": _mutation_fails(provider_collision),
        "PF-08": model_rejects_evidence(self_approval=True),
        "PF-09": model_rejects_expired_lease(),
        "PF-10": model_rejects_evidence(signature_valid=False),
        "PF-11": _mutation_fails(protected_write),
        "PF-12": _mutation_fails(registry_tamper),
        "PF-13": release_path_rejects_invalid_artifact(),
        "PF-14": provider_swap_preserves_authority(),
        "PF-15": _mutation_fails(unauthorized_dispatch),
    }


def recovery_checks() -> dict[str, bool]:
    return {
        "PF-16": pause_path_revokes_and_blocks(),
        "PF-17": rollback_path_is_deterministic(),
    }


def _state(state: str, now: datetime) -> TaskState:
    return TaskState(
        "tims-software-factory",
        "preflight-task",
        state,
        0,
        now,
        "factory_controller_service",
    )


def model_rejects_evidence(*, self_approval: bool = False, signature_valid: bool = True) -> bool:
    now = datetime.now(timezone.utc)
    machine = FactoryStateMachine(_state("IMPLEMENTATION", now))
    lease = Lease(
        "preflight-lease",
        "engineering_agent",
        "engineering_agent_service",
        now + timedelta(minutes=5),
    )
    machine.issue_lease("factory_controller_service", lease, expected_version=0, now=now)
    evidence = Evidence(
        "preflight-evidence",
        "engineering_agent",
        "engineering_agent_service",
        "preflight-task",
        "preflight-lease",
        "a" * 40,
        "sha256:" + "b" * 64,
        now,
        signature_valid,
        "engineering_agent_service" if self_approval else "independent_inspector_service",
    )
    try:
        machine.transition(
            "factory_controller_service",
            "INSPECTION",
            expected_version=1,
            evidence=[evidence],
            now=now,
        )
    except EvidenceError:
        return True
    return False


def model_rejects_expired_lease() -> bool:
    now = datetime.now(timezone.utc)
    machine = FactoryStateMachine(_state("IMPLEMENTATION", now))
    try:
        machine.issue_lease(
            "factory_controller_service",
            Lease(
                "expired-preflight-lease",
                "engineering_agent",
                "engineering_agent_service",
                now - timedelta(seconds=1),
            ),
            expected_version=0,
            now=now,
        )
    except LeaseError:
        return True
    return False


def release_path_rejects_invalid_artifact() -> bool:
    release_workflow = (ROOT / ".github/workflows/release-oidc.yml").read_text(encoding="utf-8")
    deployment = Deployment(
        "a" * 40,
        "sha256:" + "b" * 64,
        f"releases/{'a' * 40}/factory-control-plane.tar.gz",
        "version-1",
        "INITIAL_RELEASE",
    )
    invalid_head = {
        "VersionId": "version-1",
        "ContentLength": 1,
        "ServerSideEncryption": "AES256",
        "Metadata": {
            "source-commit": "a" * 40,
            "sha256": deployment.artifact_digest,
        },
        "ChecksumSHA256": base64.b64encode(bytes.fromhex("c" * 64)).decode(),
    }
    try:
        validate_s3_head(invalid_head, deployment)
    except ReleaseControlError:
        return "gh attestation verify" in release_workflow and not validate_workflows(ROOT)
    return False


def pause_path_revokes_and_blocks() -> bool:
    now = datetime.now(timezone.utc)
    machine = FactoryStateMachine(_state("IMPLEMENTATION", now))
    machine.issue_lease(
        "factory_controller_service",
        Lease(
            "pause-preflight-lease",
            "engineering_agent",
            "engineering_agent_service",
            now + timedelta(minutes=5),
        ),
        expected_version=0,
        now=now,
    )
    machine.transition("factory_controller_service", "PAUSED", expected_version=1, now=now)
    try:
        machine.assert_dispatch_allowed("factory_controller_service", "pause-preflight-lease", now=now)
    except AuthorityError:
        return all(lease.revoked for lease in machine.state.leases)
    return False


def rollback_path_is_deterministic() -> bool:
    current_commit = "a" * 40
    target_commit = "c" * 40
    digest = "sha256:" + "b" * 64
    version = "target-version"

    def s(value: str) -> dict[str, str]:
        return {"S": value}

    current = {
        "Item": {
            "PK": s("FACTORY#tims-software-factory#RELEASE"),
            "SK": s("CURRENT"),
            "record_type": s("CURRENT"),
            "source_commit": s(current_commit),
            "artifact_sha256": s("sha256:" + "d" * 64),
            "release_key": s(f"releases/{current_commit}/factory-control-plane.tar.gz"),
            "object_version_id": s("current-version"),
            "updated_by": s("timbrydges"),
            "actor_id": s("214414801"),
            "authority_mode": s("owner"),
            "workflow_run": s("100"),
            "updated_at": s("2026-08-25T11:00:00Z"),
        }
    }
    target = {
        "Item": {
            "PK": s("FACTORY#tims-software-factory#RELEASE"),
            "SK": s(f"DEPLOYMENT#{target_commit}"),
            "record_type": s("DEPLOYMENT"),
            "source_commit": s(target_commit),
            "artifact_sha256": s(digest),
            "release_key": s(f"releases/{target_commit}/factory-control-plane.tar.gz"),
            "object_version_id": s(version),
            "previous_source_commit": s("INITIAL_RELEASE"),
            "actor": s("timbrydges"),
            "actor_id": s("214414801"),
            "authority_mode": s("owner"),
            "workflow_run": s("100"),
            "released_at": s("2026-08-25T10:00:00Z"),
        }
    }
    head = {
        "VersionId": version,
        "ContentLength": 1,
        "ServerSideEncryption": "AES256",
        "Metadata": {"source-commit": target_commit, "sha256": digest},
        "ChecksumSHA256": base64.b64encode(bytes.fromhex("b" * 64)).decode(),
    }
    arguments = {
        "table_name": "factory-state",
        "target_source_commit": target_commit,
        "expected_current_source_commit": current_commit,
        "reason": "preflight deterministic rollback",
        "actor": "timbrydges",
        "actor_id": "214414801",
        "workflow_run": "123",
        "rolled_back_at": "2026-08-25T12:00:00Z",
        "current_response": current,
        "target_response": target,
        "target_head": head,
    }
    first = prepare_rollback_transaction(**arguments)
    second = prepare_rollback_transaction(**arguments)
    return first == second and not validate_workflows(ROOT)


def provider_swap_preserves_authority() -> bool:
    providers = load_yaml(ROOT / "factory/profiles/providers.yaml")["profiles"]
    return all(profile.get("authority_effect") == "none" for profile in providers.values())


def _github_get(path: str) -> tuple[int, object]:
    token = os.environ.get("GITHUB_TOKEN")
    if not token:
        return 0, {"error": "GITHUB_TOKEN missing"}
    request = urllib.request.Request(
        f"https://api.github.com/repos/timbrydges/timscodefactory/{path}",
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "X-GitHub-Api-Version": "2026-03-10",
            "User-Agent": "tims-software-factory-preflight",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            return response.status, json.load(response)
    except urllib.error.HTTPError as exc:
        return exc.code, {"error": exc.reason}


def _json_contains(actual: object, expected: object) -> bool:
    """Return whether actual contains the expected JSON structure."""
    if isinstance(expected, dict):
        return isinstance(actual, dict) and all(
            key in actual and _json_contains(actual[key], value)
            for key, value in expected.items()
        )
    if isinstance(expected, list):
        return (
            isinstance(actual, list)
            and len(actual) == len(expected)
            and all(_json_contains(actual_item, expected_item) for actual_item, expected_item in zip(actual, expected))
        )
    return actual == expected


def _same_timestamp(left: object, right: object) -> bool:
    if not isinstance(left, str) or not isinstance(right, str):
        return False
    try:
        left_time = datetime.fromisoformat(left.replace("Z", "+00:00"))
        right_time = datetime.fromisoformat(right.replace("Z", "+00:00"))
    except ValueError:
        return False
    return (
        left_time.astimezone(timezone.utc).replace(microsecond=0)
        == right_time.astimezone(timezone.utc).replace(microsecond=0)
    )


def _ruleset_matches_expected(
    ruleset: object,
    expected: object,
    owner_observation: object,
) -> bool:
    if not all(isinstance(item, dict) for item in (ruleset, expected, owner_observation)):
        return False

    expected_rules = expected.get("rules", [])
    actual_rules = ruleset.get("rules", [])
    if not isinstance(expected_rules, list) or not isinstance(actual_rules, list):
        return False
    expected_by_type = {rule.get("type"): rule for rule in expected_rules if isinstance(rule, dict)}
    actual_by_type = {rule.get("type"): rule for rule in actual_rules if isinstance(rule, dict)}
    core_matches = (
        ruleset.get("name") == expected.get("name")
        and ruleset.get("target") == expected.get("target")
        and ruleset.get("enforcement") == expected.get("enforcement")
        and ruleset.get("conditions") == expected.get("conditions")
        and set(actual_by_type) == set(expected_by_type)
        and all(
            _json_contains(actual_by_type[rule_type], expected_rule)
            for rule_type, expected_rule in expected_by_type.items()
        )
    )
    if not core_matches:
        return False

    expected_bypass_actors = expected.get("bypass_actors", [])
    if len(expected_bypass_actors) != 1:
        return False
    owner_bypass = expected_bypass_actors[0]
    if "bypass_actors" in ruleset:
        return owner_bypass in ruleset.get("bypass_actors", [])

    # GitHub redacts bypass_actors unless the caller can write the ruleset.
    # GITHUB_TOKEN cannot receive that permission, so bind the owner-authenticated
    # observation to the live ruleset ID and updated_at value. Any ruleset edit
    # invalidates the observation and fails closed until Tim verifies it again.
    return (
        owner_observation.get("repository") == "timbrydges/timscodefactory"
        and owner_observation.get("ruleset_id") == ruleset.get("id")
        and owner_observation.get("ruleset_name") == ruleset.get("name")
        and _same_timestamp(
            owner_observation.get("ruleset_updated_at"),
            ruleset.get("updated_at"),
        )
        and owner_observation.get("owner_login") == "timbrydges"
        and owner_observation.get("owner_bypass") == owner_bypass
        and owner_observation.get("current_user_can_bypass") == "always"
        and owner_observation.get("verified_via") == "owner-authenticated GitHub REST API"
    )


def _environment_matches_expected(environment: object, policies_response: object) -> bool:
    if not isinstance(environment, dict) or not isinstance(policies_response, dict):
        return False
    if environment.get("name") != "production":
        return False
    if environment.get("protection_rules", []) != []:
        return False
    if environment.get("deployment_branch_policy") != {
        "protected_branches": False,
        "custom_branch_policies": True,
    }:
        return False
    policies = policies_response.get("branch_policies", [])
    return (
        isinstance(policies, list)
        and len(policies) == 1
        and isinstance(policies[0], dict)
        and policies[0].get("name") == "main"
        and policies[0].get("type") == "branch"
    )


def _oidc_prefix_matches(configuration: object) -> bool:
    return (
        isinstance(configuration, dict)
        and configuration.get("sub_claim_prefix") == EXPECTED_OIDC_PREFIX
    )


def live_checks() -> dict[str, bool]:
    status_rules, rulesets = _github_get("rulesets")
    status_env, environment = _github_get("environments/production")
    status_policies, policies_response = _github_get(
        "environments/production/deployment-branch-policies?per_page=100"
    )
    status_oidc, oidc_configuration = _github_get("actions/oidc/customization/sub")
    ruleset_summary = next(
        (
            item
            for item in rulesets
            if isinstance(rulesets, list)
            and item.get("name") == "factory-main-protected"
            and item.get("enforcement") == "active"
        ),
        None,
    )
    status_ruleset, ruleset = (
        _github_get(f"rulesets/{ruleset_summary['id']}")
        if ruleset_summary
        else (0, {})
    )
    expected_ruleset = json.loads(
        (ROOT / "config/github/main-branch-ruleset.json").read_text(encoding="utf-8")
    )
    owner_observation = json.loads(
        (ROOT / "config/github/main-branch-ruleset-observation.json").read_text(encoding="utf-8")
    )
    ruleset_active = (
        status_rules == 200
        and status_ruleset == 200
        and _ruleset_matches_expected(ruleset, expected_ruleset, owner_observation)
    )
    environment_protected = (
        status_env == 200
        and status_policies == 200
        and _environment_matches_expected(environment, policies_response)
    )
    oidc_prefix_bound = (
        status_oidc == 200
        and _oidc_prefix_matches(oidc_configuration)
    )
    return {
        "PF-19": ruleset_active,
        "PF-20": environment_protected,
        "PF-21": oidc_prefix_bound,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=["static", "live", "all"], default="static")
    args = parser.parse_args()
    checks = {}
    checks.update(static_checks())
    checks.update(adversarial_checks())
    checks.update(recovery_checks())
    if args.mode in {"live", "all"}:
        checks.update(live_checks())
    failures = []
    for case_id in sorted(checks):
        state = "PASS" if checks[case_id] else "FAIL"
        print(f"{case_id}: {state}")
        if not checks[case_id]:
            failures.append(case_id)
    if failures:
        print(f"Preflight failed closed: {', '.join(failures)}")
        return 1
    print("F3.1 preflight passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
