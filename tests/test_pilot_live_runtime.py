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
    assert policy["budget_ledger_id"] == "tims-factory-pilot-001"
    assert policy["cumulative_reservation_required"] is True
    assert policy["maximum_remediation_cycles"] == 2
    assert policy["maximum_dispatches"] == 3
    assert sum(float(item["reserved_cost_usd"]) for item in policy["providers"].values()) == 3.0
    assert policy["providers"]["planner"]["model_id"] == "gpt-5.6-sol"
    assert policy["providers"]["builder"]["model_id"] == "gpt-5.6-sol"
    assert (
        policy["providers"]["inspector"]["model_id"]
        == "us.anthropic.claude-sonnet-4-5-20250929-v1:0"
    )
    assert policy["providers"]["builder"]["provider_family"] != policy["providers"]["inspector"]["provider_family"]
    assert policy["providers"]["planner"]["max_output_tokens"] == 8192
    assert policy["providers"]["builder"]["max_output_tokens"] == 16384
    assert policy["providers"]["inspector"]["max_output_tokens"] == 4096


def test_openai_runtime_has_bounded_long_request_and_medium_reasoning():
    source = RUNTIME_PATH.read_text(encoding="utf-8")
    assert '"reasoning": {"effort": "medium"}' in source
    assert 'urlopen(req, timeout=300)' in source
    assert 'OpenAI request exceeded 300-second bounded timeout' in source


def test_bedrock_structured_output_accepts_bare_json_or_one_complete_fence():
    expected = {
        "verdict": "APPROVE",
        "summary": "The implementation satisfies the contract.",
        "findings": [],
    }
    raw = json.dumps(expected)
    assert runtime._decode_bedrock_structured_output(raw) == expected
    assert runtime._decode_bedrock_structured_output(f"```json\n{raw}\n```") == expected


def test_bedrock_structured_output_rejects_prose_or_broken_fences():
    raw = json.dumps(
        {
            "verdict": "APPROVE",
            "summary": "The implementation satisfies the contract.",
            "findings": [],
        }
    )
    for malformed in (f"Result:\n{raw}", f"```json\n{raw}", f"```json\n{raw}\n```\nextra"):
        try:
            runtime._decode_bedrock_structured_output(malformed)
        except runtime.PilotRuntimeError:
            pass
        else:
            raise AssertionError("malformed Bedrock output was accepted")


def test_dynamodb_transaction_token_respects_aws_36_char_limit_and_surfaces_stderr():
    source = RUNTIME_PATH.read_text(encoding="utf-8")
    assert 'hexdigest()[:30]' in source
    assert 'hexdigest()[:32]' not in source
    assert 'detail = (exc.stderr or "").strip()' in source


def test_init_state_atomically_reserves_cumulative_budget_before_provider_calls():
    captured = []
    original = runtime._aws_json

    def capture(arguments, *, timeout=60):
        path = Path(arguments[arguments.index("--transact-items") + 1].removeprefix("file://"))
        captured.append((arguments, json.loads(path.read_text(encoding="utf-8"))))
        return {}

    runtime._aws_json = capture
    try:
        runtime.init_state(
            table="factory-state",
            task_id="pilot-123-1",
            run_id="123",
            ledger_id="tims-factory-pilot-001",
            provider_reserved_usd="3.00",
            hard_stop_usd="10.00",
            maximum_dispatches=3,
        )
    finally:
        runtime._aws_json = original

    assert len(captured) == 1
    arguments, transaction = captured[0]
    assert arguments[:2] == ["dynamodb", "transact-write-items"]
    assert len(arguments[arguments.index("--client-request-token") + 1]) <= 36
    assert len(transaction) == 3

    ledger = transaction[0]["Update"]
    assert ledger["Key"]["PK"]["S"] == (
        "FACTORY#tims-software-factory#BUDGET#tims-factory-pilot-001"
    )
    assert "dispatch_count < :maximum" in ledger["ConditionExpression"]
    assert "reserved_microusd <= :max_before" in ledger["ConditionExpression"]
    assert ledger["ExpressionAttributeValues"][":reserve"] == {"N": "3000000"}
    assert ledger["ExpressionAttributeValues"][":max_before"] == {"N": "7000000"}
    assert ledger["ExpressionAttributeValues"][":maximum"] == {"N": "3"}

    reservation = transaction[1]["Put"]["Item"]
    assert reservation["SK"]["S"] == "RESERVATION#pilot-123-1"
    state = transaction[2]["Put"]["Item"]
    assert state["PK"]["S"] == "FACTORY#tims-software-factory#TASK#pilot-123-1"
    payload = json.loads(state["payload"]["S"])
    assert payload["provider_reserved_usd"] == "3.00"
    assert payload["budget_ledger_id"] == "tims-factory-pilot-001"


def test_budget_reservation_retry_accepts_only_matching_committed_dispatch():
    original = runtime._aws_json
    calls = []

    def existing_dispatch(arguments, *, timeout=60):
        calls.append(arguments)
        if arguments[1] == "transact-write-items":
            raise runtime.PilotRuntimeError("idempotent request parameters changed")
        key = json.loads(arguments[arguments.index("--key") + 1])
        sk = key["SK"]["S"]
        if sk.startswith("RESERVATION#"):
            item = {
                "task_id": {"S": "pilot-123-1"},
                "workflow_run_id": {"S": "123"},
                "reserved_microusd": {"N": "3000000"},
            }
        elif sk == "STATE":
            item = {
                "state": {"S": "PILOT_PLANNING"},
                "payload": {
                    "S": json.dumps(
                        {
                            "task_id": "pilot-123-1",
                            "workflow_run_id": "123",
                            "budget_ledger_id": "tims-factory-pilot-001",
                            "provider_reserved_usd": "3.00",
                        }
                    )
                },
            }
        else:
            item = {
                "hard_stop_microusd": {"N": "10000000"},
                "maximum_dispatches": {"N": "3"},
            }
        return {"Item": item}

    runtime._aws_json = existing_dispatch
    try:
        runtime.init_state(
            table="factory-state",
            task_id="pilot-123-1",
            run_id="123",
            ledger_id="tims-factory-pilot-001",
            provider_reserved_usd="3.00",
            hard_stop_usd="10.00",
            maximum_dispatches=3,
        )
    finally:
        runtime._aws_json = original

    assert len(calls) == 4

    runtime._aws_json = existing_dispatch
    try:
        try:
            runtime.init_state(
                table="factory-state",
                task_id="pilot-123-1",
                run_id="changed",
                ledger_id="tims-factory-pilot-001",
                provider_reserved_usd="3.00",
                hard_stop_usd="10.00",
                maximum_dispatches=3,
            )
        except runtime.PilotRuntimeError:
            pass
        else:
            raise AssertionError("conflicting committed dispatch was accepted")
    finally:
        runtime._aws_json = original


def test_provider_usage_is_validated_and_persisted_atomically():
    usage = runtime._provider_usage(
        {"usage": {"input_tokens": 10, "output_tokens": 5, "total_tokens": 15}},
        provider_family="openai",
        model_id="gpt-5.6-sol",
        input_key="input_tokens",
        output_key="output_tokens",
        total_key="total_tokens",
    )
    assert usage["total_tokens"] == 15

    captured = []
    original = runtime._aws_json

    def capture(arguments, *, timeout=60):
        path = Path(arguments[arguments.index("--transact-items") + 1].removeprefix("file://"))
        captured.append((arguments, json.loads(path.read_text(encoding="utf-8"))))
        return {}

    policy = json.loads(
        (ROOT / "config/github/pilot-repo/provider-policy.json").read_text(encoding="utf-8")
    )
    runtime._aws_json = capture
    try:
        with tempfile.TemporaryDirectory() as raw:
            usage_path = Path(raw) / "usage.json"
            usage_path.write_text(
                json.dumps({**usage, "role": "planner"}),
                encoding="utf-8",
            )
            runtime.record_provider_usage(
                table="factory-state",
                task_id="pilot-123-1",
                ledger_id="tims-factory-pilot-001",
                usage_path=usage_path,
                providers=policy["providers"],
            )
    finally:
        runtime._aws_json = original

    assert len(captured) == 1
    arguments, transaction = captured[0]
    assert len(arguments[arguments.index("--client-request-token") + 1]) <= 36
    assert len(transaction) == 4
    assert transaction[0]["ConditionCheck"]["Key"]["SK"]["S"] == "RESERVATION#pilot-123-1"
    assert transaction[1]["ConditionCheck"]["Key"]["SK"]["S"] == "STATE"
    ledger = transaction[2]["Update"]
    assert "actual_total_tokens :total" in ledger["UpdateExpression"]
    assert ledger["ExpressionAttributeValues"][":total"] == {"N": "15"}
    record = transaction[3]["Put"]["Item"]
    assert record["SK"]["S"] == "USAGE#pilot-123-1#planner"
    assert record["model_id"]["S"] == "gpt-5.6-sol"


def test_provider_usage_retry_accepts_only_matching_committed_record():
    policy = json.loads(
        (ROOT / "config/github/pilot-repo/provider-policy.json").read_text(encoding="utf-8")
    )
    provider = policy["providers"]["planner"]
    original = runtime._aws_json

    def existing_usage(arguments, *, timeout=60):
        if arguments[1] == "transact-write-items":
            raise runtime.PilotRuntimeError("idempotent request parameters changed")
        key = json.loads(arguments[arguments.index("--key") + 1])
        sk = key["SK"]["S"]
        if sk.startswith("USAGE#"):
            item = {
                "task_id": {"S": "pilot-123-1"},
                "role": {"S": "planner"},
                "provider_family": {"S": provider["provider_family"]},
                "model_id": {"S": provider["model_id"]},
                "input_tokens": {"N": "10"},
                "output_tokens": {"N": "5"},
                "total_tokens": {"N": "15"},
            }
        elif sk.startswith("RESERVATION#"):
            item = {"task_id": {"S": "pilot-123-1"}}
        elif sk == "STATE":
            item = {"state": {"S": "PILOT_PLANNING"}}
        else:
            item = {
                "usage_record_count": {"N": "1"},
                "actual_input_tokens": {"N": "10"},
                "actual_output_tokens": {"N": "5"},
                "actual_total_tokens": {"N": "15"},
            }
        return {"Item": item}

    runtime._aws_json = existing_usage
    try:
        with tempfile.TemporaryDirectory() as raw:
            usage_path = Path(raw) / "usage.json"
            usage_path.write_text(
                json.dumps(
                    {
                        "schema_version": "1.0",
                        "role": "planner",
                        "provider_family": provider["provider_family"],
                        "model_id": provider["model_id"],
                        "input_tokens": 10,
                        "output_tokens": 5,
                        "total_tokens": 15,
                    }
                ),
                encoding="utf-8",
            )
            runtime.record_provider_usage(
                table="factory-state",
                task_id="pilot-123-1",
                ledger_id="tims-factory-pilot-001",
                usage_path=usage_path,
                providers=policy["providers"],
            )
            usage_path.write_text(
                usage_path.read_text(encoding="utf-8").replace(
                    '"output_tokens": 5', '"output_tokens": 6'
                ).replace('"total_tokens": 15', '"total_tokens": 16'),
                encoding="utf-8",
            )
            try:
                runtime.record_provider_usage(
                    table="factory-state",
                    task_id="pilot-123-1",
                    ledger_id="tims-factory-pilot-001",
                    usage_path=usage_path,
                    providers=policy["providers"],
                )
            except runtime.PilotRuntimeError:
                pass
            else:
                raise AssertionError("conflicting provider usage was accepted")
    finally:
        runtime._aws_json = original


def test_provider_usage_rejects_missing_or_inconsistent_counts():
    malformed = [
        {},
        {"usage": {"input_tokens": 1, "output_tokens": 2, "total_tokens": 4}},
        {"usage": {"input_tokens": True, "output_tokens": 2, "total_tokens": 3}},
    ]
    for payload in malformed:
        try:
            runtime._provider_usage(
                payload,
                provider_family="openai",
                model_id="gpt-5.6-sol",
                input_key="input_tokens",
                output_key="output_tokens",
                total_key="total_tokens",
            )
        except runtime.PilotRuntimeError:
            pass
        else:
            raise AssertionError("malformed provider usage was accepted")


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
    assert "PILOT_STATUS: RETIRED" in workflow
    assert workflow.count('test "$PILOT_STATUS" = "OWNER_APPROVED_LIVE_PILOT"') == 2
    assert "AWS_PILOT_RUNTIME_ROLE_ARN" in workflow
    assert "OPENAI_API_KEY" in workflow
    assert "planner / bind architecture provenance" in workflow
    assert "Planner-authorized paths to an evidence branch" in workflow
    assert "independent Claude review" in workflow
    assert "FACTORY_INSPECTOR_APP_PRIVATE_KEY" in workflow
    assert "--expected-state PILOT_INSPECTING" in workflow
    assert "--next-state PILOT_RELEASE_READY" in workflow
    assert "--evidence \"$RUNNER_TEMP/release-evidence.json\"" in workflow
    assert workflow.count("record-usage") == 3
    assert "--usage-output \"$RUNNER_TEMP/inspector-usage.json\"" in workflow
    assert "planner-evidence/provider-usage.json" in workflow
    assert "builder-evidence/provider-usage.json" in workflow
    assert 'find "$RUNNER_TEMP/builder" -type d -name __pycache__' in workflow
    assert "-name '*.pyc' -o -name '*.pyo'" in workflow
    for action in (
        "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1",
        "actions/create-github-app-token@bcd2ba49218906704ab6c1aa796996da409d3eb1",
        "aws-actions/configure-aws-credentials@e6de054238d6b7531b4efff3b6587d9aade6a06c",
        "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a",
        "actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c",
    ):
        assert action in workflow


def test_post_pilot_control_verification_is_owner_only_and_model_free():
    workflow = (ROOT / "config/github/pilot-repo/pilot-live.yml").read_text(encoding="utf-8")
    verification = workflow.split("  verify-controls:", 1)[1].split("  preflight:", 1)[0]
    assert "if: ${{ inputs.verify_controls }}" in verification
    assert 'test "$GITHUB_ACTOR" = "$EXPECTED_OWNER"' in verification
    assert 'test "$GITHUB_REPOSITORY" = "$EXPECTED_REPOSITORY"' in verification
    assert 'test "$PILOT_STATUS" = "RETIRED"' in verification
    assert "verify-budget-controls" in verification
    assert "provider-controls-evidence.json" in verification
    assert "OPENAI_API_KEY" not in verification
    assert "bedrock-runtime" not in verification
    assert "inputs.recovery_pr == '' && !inputs.verify_controls" in workflow
    assert "inputs.recovery_pr != '' && !inputs.verify_controls" in workflow


def test_pilot_runtime_aws_role_is_immutable_and_owner_only():
    terraform = (ROOT / "infra/aws/pilot_runtime.tf").read_text(encoding="utf-8")
    assert 'default     = "timbrydges/tims-factory-pilot"' in terraform
    assert 'default     = "1368587958"' in terraform
    assert 'variable = "token.actions.githubusercontent.com:actor_id"' in terraform
    assert 'values   = [var.pilot_github_repository_owner_id]' in terraform
    assert 'values   = ["pilot-live"]' in terraform
    assert 'token.actions.githubusercontent.com:event_name' not in terraform
    assert (
        'pilot_bedrock_profile_id       = "us.anthropic.claude-sonnet-4-5-20250929-v1:0"'
        in terraform
    )
    assert (
        'pilot_bedrock_model_id         = "anthropic.claude-sonnet-4-5-20250929-v1:0"'
        in terraform
    )
    assert '"${aws_s3_bucket.factory_releases.arn}/pilot-releases/*"' in terraform
    assert 'policy_arn = aws_iam_policy.controller_state.arn' in terraform
    assert '"FACTORY#tims-software-factory#BUDGET#*"' in (
        ROOT / "infra/aws/main.tf"
    ).read_text(encoding="utf-8")
