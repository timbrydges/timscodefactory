from __future__ import annotations

import importlib.util
import json
import shutil
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RUNTIME_PATH = ROOT / "config/github/pilot-repo/pilot_runtime.py"

spec = importlib.util.spec_from_file_location("pilot_runtime_template", RUNTIME_PATH)
assert spec and spec.loader
runtime = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runtime)


def _runtime_root(tmp: Path) -> Path:
    factory = tmp / ".factory"
    factory.mkdir(parents=True)
    shutil.copy2(ROOT / "config/github/pilot-repo/pilot-task.json", factory / "pilot-task.json")
    shutil.copy2(ROOT / "config/github/pilot-repo/provider-policy.json", factory / "provider-policy.json")
    return tmp


def test_live_pilot_contracts_are_exact_and_bounded():
    with tempfile.TemporaryDirectory() as raw:
        task, policy = runtime.load_contracts(_runtime_root(Path(raw)))
    assert task["feature"]["name"] == "deterministic_release_readiness_checklist"
    assert [item["id"] for item in task["acceptance_tests"]] == [f"AT-{i:02d}" for i in range(1, 9)]
    assert policy["max_provider_calls_per_run"] == 3
    assert sum(float(item["reserved_cost_usd"]) for item in policy["providers"].values()) == 3.0
    assert policy["providers"]["planner"]["model_id"] == "gpt-5.6-sol"
    assert policy["providers"]["builder"]["model_id"] == "gpt-5.6-sol"
    assert policy["providers"]["inspector"]["model_id"] == "us.anthropic.claude-sonnet-5"
    assert policy["providers"]["builder"]["provider_family"] != policy["providers"]["inspector"]["provider_family"]


def test_builder_output_rejects_unauthorized_or_duplicate_paths():
    valid = [
        {"path": path, "content": "x"}
        for path in sorted(runtime.EXPECTED_BUILDER_PATHS)
    ]
    assert {item["path"] for item in runtime.validate_builder_files(valid)} == runtime.EXPECTED_BUILDER_PATHS

    bad = list(valid)
    bad[0] = {"path": ".github/workflows/escape.yml", "content": "x"}
    try:
        runtime.validate_builder_files(bad)
    except runtime.PilotRuntimeError:
        pass
    else:
        raise AssertionError("unauthorized Builder path was accepted")

    duplicate = list(valid)
    duplicate[-1] = dict(duplicate[0])
    try:
        runtime.validate_builder_files(duplicate)
    except runtime.PilotRuntimeError:
        pass
    else:
        raise AssertionError("duplicate Builder path was accepted")


def test_release_package_is_byte_for_byte_deterministic():
    with tempfile.TemporaryDirectory() as raw:
        root = Path(raw)
        (root / "src").mkdir()
        (root / "tests/unit").mkdir(parents=True)
        (root / "docs/implementation").mkdir(parents=True)
        (root / "src/app.py").write_text("print('ok')\n", encoding="utf-8")
        (root / "tests/unit/test_app.py").write_text("# test\n", encoding="utf-8")
        (root / "docs/implementation/README.md").write_text("implementation\n", encoding="utf-8")
        (root / ".factory").mkdir()
        (root / ".factory/secret.txt").write_text("must-not-package\n", encoding="utf-8")

        first = root / "first.tar.gz"
        second = root / "second.tar.gz"
        first_digest = runtime.deterministic_package(root, first)
        second_digest = runtime.deterministic_package(root, second)

        assert first_digest == second_digest
        assert first.read_bytes() == second.read_bytes()
        assert b"must-not-package" not in first.read_bytes()


def test_pilot_workflow_is_owner_dispatched_and_role_separated():
    workflow = (ROOT / "config/github/pilot-repo/pilot-live.yml").read_text(encoding="utf-8")
    assert "workflow_dispatch:" in workflow
    assert "pull_request_target" not in workflow
    assert "EXPECTED_OWNER: timbrydges" in workflow
    assert "AWS_PILOT_RUNTIME_ROLE_ARN" in workflow
    assert "OPENAI_API_KEY" in workflow
    assert "planner / bind architecture provenance" in workflow
    assert "Planner-authorized paths to an evidence branch" in workflow
    assert "independent Claude review" in workflow
    assert "FACTORY_INSPECTOR_APP_PRIVATE_KEY" in workflow
    assert "--expected-state PILOT_INSPECTING" in workflow
    assert "--next-state PILOT_RELEASE_READY" in workflow
    assert "--evidence \"$RUNNER_TEMP/release-evidence.json\"" in workflow
    for action in (
        "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1",
        "actions/create-github-app-token@bcd2ba49218906704ab6c1aa796996da409d3eb1",
        "aws-actions/configure-aws-credentials@e6de054238d6b7531b4efff3b6587d9aade6a06c",
        "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a",
        "actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c",
    ):
        assert action in workflow


def test_pilot_runtime_aws_role_is_immutable_and_owner_only():
    terraform = (ROOT / "infra/aws/pilot_runtime.tf").read_text(encoding="utf-8")
    assert 'default     = "timbrydges/tims-factory-pilot"' in terraform
    assert 'default     = "1368587958"' in terraform
    assert 'variable = "token.actions.githubusercontent.com:actor_id"' in terraform
    assert 'values   = [var.pilot_github_repository_owner_id]' in terraform
    assert 'values   = ["pilot-live"]' in terraform
    assert 'values   = ["workflow_dispatch"]' in terraform
    assert 'pilot_bedrock_profile_id       = "us.anthropic.claude-sonnet-5"' in terraform
    assert '"${aws_s3_bucket.factory_releases.arn}/pilot-releases/*"' in terraform
    assert 'policy_arn = aws_iam_policy.controller_state.arn' in terraform
