#!/usr/bin/env python3
"""Validate the F3.1 registry and all permission-profile invariants."""

from __future__ import annotations

import argparse
import fnmatch
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import jsonschema
import yaml

try:
    from scripts.build_manifest import render_manifest
except ModuleNotFoundError:  # direct `python scripts/validate_registry.py`
    from build_manifest import render_manifest


EXPECTED_ROLES = {
    "deep_security_reviewer",
    "engineering_agent",
    "factory_controller",
    "factory_owner",
    "independent_inspector",
    "product_spec_author",
    "product_spec_reviewer",
    "qa_engineer",
    "release_automation",
    "software_architect",
    "specialist_reviewer",
}
PROTECTED_PREFIXES = ("factory/", ".github/", "infra/")
REVIEW_ROLES = {
    "deep_security_reviewer",
    "independent_inspector",
    "product_spec_reviewer",
    "specialist_reviewer",
}
OWNER_AUTHORITY = {
    "ultimate_authority": True,
    "approval_required": False,
    "may_approve_own_changes": True,
    "may_bypass_all_gates": True,
    "may_intervene_at_any_stage": True,
    "may_pause_or_stop": True,
    "may_resume": True,
    "may_override_all_agents": True,
    "owner_actions_audited": True,
    "authority_delegable": False,
}


@dataclass(frozen=True)
class ValidationResult:
    errors: tuple[str, ...]

    @property
    def ok(self) -> bool:
        return not self.errors


def load_yaml(path: Path) -> dict[str, Any]:
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"{path}: expected YAML mapping")
    return data


def _path_may_touch_protected(pattern: str) -> bool:
    literal = pattern.split("*")[0]
    return pattern == "**" or any(
        literal.startswith(prefix) or prefix.startswith(literal)
        for prefix in PROTECTED_PREFIXES
    )


def validate(root: Path, *, check_manifest: bool = True) -> ValidationResult:
    errors: list[str] = []
    factory = root / "factory"
    try:
        registry = load_yaml(factory / "registry.yaml")
    except Exception as exc:  # fail closed at the registry boundary
        return ValidationResult((f"registry load failed: {exc}",))

    repository = registry.get("repository", {})
    if repository.get("full_name") != "timbrydges/timscodefactory":
        errors.append("repository binding must be timbrydges/timscodefactory")
    if repository.get("visibility") != "public":
        errors.append("control-plane repository visibility must be public")
    if repository.get("default_branch") != "main":
        errors.append("default branch must be main")
    if repository.get("owner_bypass_actor_id") != 214414801:
        errors.append("repository owner bypass must be bound to Tim's GitHub user ID")
    if repository.get("owner_bypass_mode") != "always":
        errors.append("Tim's repository owner bypass must always be available")
    if registry.get("mode") not in {"PAUSED", "PILOT", "ACTIVE"}:
        errors.append("registry mode is unknown")

    try:
        environment = json.loads(
            (root / "config/github/production-environment.json").read_text(encoding="utf-8")
        )
        ruleset = json.loads(
            (root / "config/github/main-branch-ruleset.json").read_text(encoding="utf-8")
        )
        deployment_branch = json.loads(
            (root / "config/github/production-deployment-branch-policy.json").read_text(
                encoding="utf-8"
            )
        )
    except Exception as exc:
        errors.append(f"GitHub production environment configuration is invalid: {exc}")
    else:
        if environment.get("wait_timer") != 0:
            errors.append("production environment wait timer must be disabled")
        if environment.get("prevent_self_review") is not False:
            errors.append("Tim must be permitted to approve his own production workflow")
        if environment.get("reviewers") != [{"type": "User", "id": 214414801}]:
            errors.append("production environment reviewer must be timbrydges")
        if environment.get("deployment_branch_policy") != {
            "protected_branches": False,
            "custom_branch_policies": True,
        }:
            errors.append("production environment must use custom deployment branch policies")
        if deployment_branch != {"name": "main", "type": "branch"}:
            errors.append("production deployment branch policy must match only main")
        if ruleset.get("bypass_actors") != [
            {"actor_id": 214414801, "actor_type": "User", "bypass_mode": "always"}
        ]:
            errors.append("main ruleset must grant Tim an always-on personal bypass")

    owner_registry = registry.get("owner_authority", {})
    if owner_registry != {"identity": "tim_brydges", "human_owner": True, **OWNER_AUTHORITY}:
        errors.append("registry must declare Tim's complete and non-delegable owner authority")
    if registry.get("runtime_state", {}).get("authoritative_writers") != [
        "factory_controller",
        "factory_owner",
    ]:
        errors.append("runtime state must permit controller writes and Tim owner overrides")
    invariants = registry.get("invariants", {})
    if invariants.get("dispatch_authorities") != ["factory_controller", "factory_owner"]:
        errors.append("registry dispatch authorities must be controller and Factory Owner")
    if not all(
        invariants.get(key) is True
        for key in (
            "agent_self_approval_prohibited",
            "owner_self_approval_permitted",
            "owner_bypass_is_absolute",
            "owner_stop_is_immediate",
        )
    ):
        errors.append("registry invariants must preserve Tim's authority and agent separation")
    release = registry.get("release", {})
    if not (
        release.get("require_owner_approval_for_agent_release") is True
        and release.get("owner_may_self_approve") is True
        and release.get("owner_may_bypass_approval") is True
    ):
        errors.append("release policy must distinguish agent gates from Tim's owner authority")

    schema = json.loads((factory / "schemas/role-contract.schema.json").read_text(encoding="utf-8"))
    roles: dict[str, dict[str, Any]] = {}
    referenced_paths = registry.get("roles", [])
    for relative in referenced_paths:
        path = factory / relative
        if not path.is_file():
            errors.append(f"missing role contract: {relative}")
            continue
        try:
            role = load_yaml(path)
            jsonschema.Draft202012Validator(schema).validate(role)
        except Exception as exc:
            errors.append(f"invalid role contract {relative}: {exc}")
            continue
        role_id = role["role_id"]
        if role_id in roles:
            errors.append(f"duplicate role id: {role_id}")
        roles[role_id] = role

    unknown = set(roles) - EXPECTED_ROLES
    missing = EXPECTED_ROLES - set(roles)
    if unknown:
        errors.append(f"unknown roles: {sorted(unknown)}")
    if missing:
        errors.append(f"missing roles: {sorted(missing)}")
    if len(referenced_paths) != 11:
        errors.append("registry must reference exactly 11 role contracts")

    profile_docs: dict[str, dict[str, Any]] = {}
    for profile_type, relative in registry.get("profiles", {}).items():
        path = factory / relative
        if not path.is_file():
            errors.append(f"missing {profile_type} profile file: {relative}")
            continue
        try:
            profile_docs[profile_type] = load_yaml(path)
        except Exception as exc:
            errors.append(f"invalid {profile_type} profile file: {exc}")

    providers = profile_docs.get("providers", {}).get("profiles", {})
    credentials = profile_docs.get("credentials", {}).get("profiles", {})
    networks = profile_docs.get("networks", {}).get("profiles", {})
    for role_id, role in roles.items():
        credential = role["credential_profile"]
        provider = role["provider_profile"]
        network = role["network_policy"]
        if credential not in credentials:
            errors.append(f"{role_id}: unknown credential profile {credential}")
        if provider is not None and provider not in providers:
            errors.append(f"{role_id}: unknown provider profile {provider}")
        if network not in networks:
            errors.append(f"{role_id}: unknown network profile {network}")
        if role["gate_authority"]["may_dispatch"] and role_id not in {
            "factory_controller",
            "factory_owner",
        }:
            errors.append(f"{role_id}: only factory_controller or factory_owner may dispatch")
        if role_id in REVIEW_ROLES:
            if role["writable_paths"]:
                errors.append(f"{role_id}: reviewer must not have writable paths")
            if role["github_permissions"].get("contents") == "write":
                errors.append(f"{role_id}: reviewer must not have contents write")
        if role_id != "factory_owner" and "owner_authority" in role:
            errors.append(f"{role_id}: ultimate owner authority cannot be delegated")
        if role_id not in {"factory_owner"}:
            for pattern in role["writable_paths"]:
                if _path_may_touch_protected(pattern):
                    errors.append(f"{role_id}: writable path can touch protected controls: {pattern}")

    if {r for r, v in roles.items() if v["gate_authority"]["may_dispatch"]} != {
        "factory_controller",
        "factory_owner",
    }:
        errors.append("controller-and-owner dispatch invariant failed")

    owner = roles.get("factory_owner")
    if owner:
        if owner.get("owner_authority") != OWNER_AUTHORITY:
            errors.append("factory_owner must retain complete owner authority")
        if owner["identity_constraints"].get("cannot_review_own_work") is not False:
            errors.append("factory_owner must be permitted to approve Tim's own work")
        if owner["gate_authority"].get("may_approve") != ["*"]:
            errors.append("factory_owner approval authority must cover every gate")
        if owner.get("allowed_states") != [
            "PAUSED",
            "INTAKE",
            "SPECIFICATION",
            "SPEC_REVIEW",
            "ARCHITECTURE",
            "IMPLEMENTATION",
            "INSPECTION",
            "QA",
            "SECURITY_REVIEW",
            "RELEASE_READY",
            "RELEASING",
            "RELEASED",
            "STALLED",
            "REMEDIATION",
        ]:
            errors.append("factory_owner must be authorized in every Factory state")

    controller = roles.get("factory_controller")
    if controller and controller["github_permissions"].get("actions") != "write":
        errors.append("factory_controller requires actions write to dispatch release workflows")
    controller_credential = credentials.get("controller_service", {})
    if controller_credential.get("github_actions") != "write":
        errors.append("controller_service credential requires GitHub Actions write")
    owner_credential = credentials.get("owner_human", {})
    if owner_credential.get("ruleset_bypass") != "always":
        errors.append("owner_human credential must retain the ruleset bypass")
    if owner_credential.get("production_approval") != "approve_self_or_bypass":
        errors.append("owner_human credential must permit self-approval or bypass")

    pairs = [
        ("engineering_agent", "independent_inspector"),
        ("product_spec_author", "product_spec_reviewer"),
    ]
    for author_id, reviewer_id in pairs:
        author = roles.get(author_id)
        reviewer = roles.get(reviewer_id)
        if not author or not reviewer:
            continue
        if author["identity_constraints"]["authoritative_identity"] == reviewer["identity_constraints"]["authoritative_identity"]:
            errors.append(f"identity collision: {author_id} and {reviewer_id}")
        author_provider = providers.get(author["provider_profile"], {})
        reviewer_provider = providers.get(reviewer["provider_profile"], {})
        if author_id == "engineering_agent" and author_provider.get("provider_family") == reviewer_provider.get("provider_family"):
            errors.append("Pilot #1 engineering and inspector provider families must differ")

    release_credential = credentials.get("release_oidc_workflow", {})
    expected_subject = (
        f"repo:{repository.get('full_name')}:environment:"
        f"{repository.get('protected_environment')}"
    )
    if release_credential.get("cloud_subject") != expected_subject:
        errors.append("OIDC release subject is not bound to repository and production environment")
    if release_credential.get("long_lived_cloud_secret") != "prohibited":
        errors.append("release identity must prohibit long-lived cloud secrets")

    integrity = profile_docs.get("controller_integrity", {})
    if integrity.get("authoritative_state_writers") != ["factory_controller", "factory_owner"]:
        errors.append("authoritative state writers must be the controller and Tim")
    if integrity.get("default_transition") != "deny":
        errors.append("state transitions must default deny")
    integrity_rules = integrity.get("rules", {})
    if integrity_rules.get("dispatch_authorities") != ["factory_controller", "factory_owner"]:
        errors.append("dispatch must permit both controller and Factory Owner")
    if not all(
        integrity_rules.get(key) is True
        for key in (
            "owner_authority_is_ultimate",
            "owner_can_override_any_gate",
            "owner_can_stop_at_any_stage",
            "owner_override_requires_audit",
        )
    ):
        errors.append("controller integrity profile must preserve Tim's ultimate authority")

    if check_manifest:
        manifest_path = root / "MANIFEST.sha256"
        if not manifest_path.exists():
            errors.append("MANIFEST.sha256 is missing")
        elif manifest_path.read_text(encoding="utf-8") != render_manifest(root):
            errors.append("MANIFEST.sha256 does not match repository contents")

    return ValidationResult(tuple(errors))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--skip-manifest", action="store_true")
    args = parser.parse_args()
    result = validate(args.root, check_manifest=not args.skip_manifest)
    if result.ok:
        print("F3.1 registry validation passed")
        return 0
    for error in result.errors:
        print(f"ERROR: {error}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
