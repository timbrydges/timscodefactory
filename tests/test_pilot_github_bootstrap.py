from __future__ import annotations

import json
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]


def load_yaml(path: str):
    return yaml.safe_load((ROOT / path).read_text(encoding="utf-8"))


def load_json(path: str):
    return json.loads((ROOT / path).read_text(encoding="utf-8"))


def test_pilot_ruleset_is_fail_closed():
    ruleset = load_json("config/github/pilot-main-branch-ruleset.json")
    assert ruleset["name"] == "pilot-main-protected"
    assert ruleset["enforcement"] == "active"
    types = {rule["type"] for rule in ruleset["rules"]}
    assert {"deletion", "non_fast_forward", "required_linear_history", "pull_request", "required_status_checks"} <= types
    checks = next(rule for rule in ruleset["rules"] if rule["type"] == "required_status_checks")
    contexts = {item["context"] for item in checks["parameters"]["required_status_checks"]}
    assert contexts == {
        "pilot-ci / validate",
        "identity-boundary / verify",
        "inspector-gate / verify",
    }
    pr = next(rule for rule in ruleset["rules"] if rule["type"] == "pull_request")["parameters"]
    assert pr["required_approving_review_count"] == 1
    assert pr["dismiss_stale_reviews_on_push"] is True
    assert pr["require_last_push_approval"] is True
    assert pr["required_review_thread_resolution"] is True
    assert pr["allowed_merge_methods"] == ["squash"]


def test_app_specs_match_authoritative_role_and_credential_profiles():
    apps = load_json("config/github/pilot-app-identities.json")["apps"]
    credentials = load_yaml("factory/profiles/credentials.yaml")["profiles"]
    roles = {
        "planner": load_yaml("factory/roles/software_architect.yaml"),
        "builder": load_yaml("factory/roles/engineering_agent.yaml"),
        "inspector": load_yaml("factory/roles/independent_inspector.yaml"),
    }
    expected = {
        "planner": "gh_architecture_writer",
        "builder": "gh_feature_writer",
        "inspector": "gh_readonly_reviewer",
    }
    identities = set()
    for name, profile_name in expected.items():
        app = apps[name]
        role = roles[name]
        profile = credentials[profile_name]
        assert app["credential_profile"] == profile_name == role["credential_profile"]
        assert profile["identity_type"] == "github_app_installation"
        assert app["authoritative_identity"] == role["identity_constraints"]["authoritative_identity"]
        identities.add(app["authoritative_identity"])
    assert len(identities) == 3

    assert apps["planner"]["allowed_merge_paths"] == ["architecture/**", "docs/adr/**"]
    assert apps["builder"]["allowed_merge_paths"] == ["src/**", "tests/unit/**", "docs/implementation/**"]
    assert apps["inspector"]["allowed_merge_paths"] == []
    assert apps["inspector"]["repository_permissions"]["contents"] == "read"


def test_pilot_workflow_templates_preserve_identity_boundaries():
    boundary = (ROOT / "config/github/pilot-repo/identity-boundary.yml").read_text(encoding="utf-8")
    inspector = (ROOT / "config/github/pilot-repo/inspector-gate.yml").read_text(encoding="utf-8")
    canary = (ROOT / "config/github/pilot-repo/identity-canary.yml").read_text(encoding="utf-8")
    combined = boundary + inspector + canary
    assert "pull_request_target" not in combined
    assert '"architecture/", "docs/adr/"' in boundary
    assert '"src/", "tests/unit/", "docs/implementation/"' in boundary
    assert "Inspector is read-only" in boundary
    assert '.state == "APPROVED" and .commit_id == $head' in inspector
    assert "FACTORY_INSPECTOR_LOGIN" in inspector
    assert "actions/create-github-app-token@bcd2ba49218906704ab6c1aa796996da409d3eb1" in canary
    assert "three_distinct_github_apps" in canary
    for secret in (
        "FACTORY_PLANNER_APP_PRIVATE_KEY",
        "FACTORY_BUILDER_APP_PRIVATE_KEY",
        "FACTORY_INSPECTOR_APP_PRIVATE_KEY",
    ):
        assert secret in canary


def test_bootstrap_targets_only_reserved_private_pilot():
    script = (ROOT / "scripts/bootstrap_pilot_repo.py").read_text(encoding="utf-8")
    assert 'REPO = "tims-factory-pilot"' in script
    assert '"private": True' in script
    assert '"default_workflow_permissions": "read"' in script
    assert '"can_approve_pull_request_reviews": False' in script
    assert '"feature_code_written": False' in script
