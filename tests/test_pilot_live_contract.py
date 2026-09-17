from __future__ import annotations

from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]


def test_operational_contract_binds_three_system_pilot_without_owner_override():
    contract = yaml.safe_load((ROOT / "factory/pilot/runtime-contract.yaml").read_text(encoding="utf-8"))
    assert contract["contract_id"] == "tims-factory-pilot-runtime-002"
    assert contract["status"] == "OWNER_APPROVED_LIVE_PILOT"
    assert contract["approval"] == {
        "owner_identity": "tim_brydges",
        "authority": "factory_owner",
        "approved_on": "2026-09-17",
        "change": "switch_inspector_to_claude_sonnet_4_5",
        "supersedes": "tims-factory-pilot-runtime-001",
    }
    assert contract["repository"] == "timbrydges/tims-factory-pilot"
    assert contract["workflow"] == "pilot-live"
    assert contract["dispatch"] == {
        "event": "workflow_dispatch",
        "owner_login": "timbrydges",
        "owner_id": "214414801",
        "ref": "refs/heads/main",
        "environment": "production",
        "maximum_concurrent_runs": 1,
    }
    assert set(contract["roles"]) == {"planner", "builder", "inspector"}
    assert contract["roles"]["planner"]["repository_effect"] == "evidence_branch_only"
    assert contract["roles"]["builder"]["repository_effect"] == "implementation_pull_request"
    assert contract["roles"]["inspector"]["repository_effect"] == "exact_head_review_only"
    assert (
        contract["roles"]["inspector"]["model"]
        == "us.anthropic.claude-sonnet-4-5-20250929-v1:0"
    )
    assert contract["roles"]["builder"]["provider_family"] != contract["roles"]["inspector"]["provider_family"]
    assert contract["failure_policy"]["owner_override_counts_as_clean_pilot_success"] is False


def test_operational_state_graph_is_bounded_and_release_terminal():
    contract = yaml.safe_load((ROOT / "factory/pilot/runtime-contract.yaml").read_text(encoding="utf-8"))
    machine = contract["state_machine"]
    assert machine["authority"] == "factory_controller_service"
    assert machine["initial_state"] == "PILOT_PLANNING"
    assert machine["terminal_state"] == "PILOT_RELEASED"
    assert machine["transitions"]["PILOT_RELEASED"] == []
    assert machine["transitions"]["PILOT_PLANNING"] == ["PILOT_BUILDING", "PILOT_STALLED"]
    assert "PILOT_RELEASED" not in machine["transitions"]["PILOT_BUILDING"]
    assert "PILOT_RELEASED" not in machine["transitions"]["PILOT_INSPECTING"]


def test_bootstrap_includes_live_runtime_templates():
    script = (ROOT / "scripts/bootstrap_pilot_repo.py").read_text(encoding="utf-8")
    for target in (
        '.gitignore',
        '.factory/pilot-task.json',
        '.factory/provider-policy.json',
        '.factory/pilot_runtime.py',
        '.github/workflows/pilot-live.yml',
    ):
        assert target in script
    assert "Operational role activation remains DENY" not in script
    assert "Live execution remains fail-closed" in script


def test_live_workflow_supports_ruleset_aware_exact_head_recovery():
    workflow = (ROOT / "config/github/pilot-repo/pilot-live.yml").read_text(encoding="utf-8")
    assert "recovery_pr:" in workflow
    assert "recovery_head:" in workflow
    assert "recovery_task_id:" in workflow
    assert "gh pr checks" not in workflow
    assert 'until gh pr merge "$PR"' in workflow
    assert "Protected merge requirements did not pass before the deadline" in workflow
    assert '.commit_id == $head' in workflow
    assert '.user.login == "tims-factory-inspector[bot]"' in workflow
    assert 'test "$(git rev-parse "${INSPECTED_HEAD}^{tree}")"' in workflow
    assert "--expected-state PILOT_INSPECTING" in workflow
    assert "--expected-version 2" in workflow


def test_pilot_oidc_trust_uses_only_aws_supported_github_claims():
    terraform = (ROOT / "infra/aws/pilot_runtime.tf").read_text(encoding="utf-8")
    supported = {
        "aud",
        "sub",
        "repository_owner_id",
        "repository_id",
        "ref",
        "environment",
        "workflow",
        "actor_id",
    }
    prefix = 'variable = "token.actions.githubusercontent.com:'
    claims = {
        line.split(prefix, 1)[1].split('"', 1)[0]
        for line in terraform.splitlines()
        if prefix in line
    }
    assert claims == supported
    assert "token.actions.githubusercontent.com:event_name" not in terraform
