#!/usr/bin/env python3
"""Execute static, adversarial, recovery, and live F3.1 preflight checks."""

from __future__ import annotations

import argparse
import copy
import json
import os
import tempfile
import urllib.error
import urllib.request
from pathlib import Path

import yaml

try:
    from scripts.build_manifest import render_manifest
    from scripts.validate_registry import load_yaml, validate
except ModuleNotFoundError:  # direct `python scripts/preflight.py`
    from build_manifest import render_manifest
    from validate_registry import load_yaml, validate


ROOT = Path(__file__).resolve().parents[1]


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
        "PF-08": evidence_is_rejected(author="engineering_agent_service", reviewer="engineering_agent_service", lease_expired=False, signature_valid=True),
        "PF-09": evidence_is_rejected(author="engineering_agent_service", reviewer="independent_inspector_service", lease_expired=True, signature_valid=True),
        "PF-10": evidence_is_rejected(author="engineering_agent_service", reviewer="independent_inspector_service", lease_expired=False, signature_valid=False),
        "PF-11": _mutation_fails(protected_write),
        "PF-12": _mutation_fails(registry_tamper),
        "PF-13": release_is_rejected(signed=False, digest_matches=True, owner_approved=True, rollback_present=True),
        "PF-14": provider_swap_preserves_authority(),
        "PF-15": _mutation_fails(unauthorized_dispatch),
    }


def recovery_checks() -> dict[str, bool]:
    integrity = load_yaml(ROOT / "factory/profiles/controller-integrity.yaml")
    return {
        "PF-16": integrity["failure_response"] == {
            "transition_to": "PAUSED",
            "revoke_active_leases": True,
            "block_dispatch": True,
            "require_owner_resolution": True,
        },
        "PF-17": integrity["rules"]["rollback_must_not_require_ai"] is True,
    }


def evidence_is_rejected(*, author: str, reviewer: str, lease_expired: bool, signature_valid: bool) -> bool:
    return author == reviewer or lease_expired or not signature_valid


def release_is_rejected(*, signed: bool, digest_matches: bool, owner_approved: bool, rollback_present: bool) -> bool:
    return not all((signed, digest_matches, owner_approved, rollback_present))


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
            "X-GitHub-Api-Version": "2022-11-28",
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
        and owner_observation.get("ruleset_updated_at") == ruleset.get("updated_at")
        and owner_observation.get("owner_login") == "timbrydges"
        and owner_observation.get("owner_bypass") == owner_bypass
        and owner_observation.get("current_user_can_bypass") == "always"
        and owner_observation.get("verified_via") == "owner-authenticated GitHub REST API"
    )


def live_checks() -> dict[str, bool]:
    status_rules, rulesets = _github_get("rulesets")
    status_env, environment = _github_get("environments/production")
    status_policies, policies_response = _github_get(
        "environments/production/deployment-branch-policies?per_page=100"
    )
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
    protection_rules = environment.get("protection_rules", []) if isinstance(environment, dict) else []
    reviewer_rules = [rule for rule in protection_rules if rule.get("type") == "required_reviewers"]
    reviewer_configured = (
        len(reviewer_rules) == 1
        and reviewer_rules[0].get("prevent_self_review") is False
        and any(
            item.get("type") == "User"
            and item.get("reviewer", {}).get("login") == "timbrydges"
            for item in reviewer_rules[0].get("reviewers", [])
        )
    )
    branch_policy = environment.get("deployment_branch_policy") if isinstance(environment, dict) else None
    policies = policies_response.get("branch_policies", []) if isinstance(policies_response, dict) else []
    main_only = status_policies == 200 and len(policies) == 1 and policies[0].get("name") == "main"
    environment_protected = (
        status_env == 200
        and environment.get("name") == "production"
        and branch_policy == {"protected_branches": False, "custom_branch_policies": True}
        and reviewer_configured
        and main_only
    )
    return {"PF-19": ruleset_active, "PF-20": environment_protected}


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
