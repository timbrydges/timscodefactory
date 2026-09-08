from __future__ import annotations

import asyncio
import json
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from factory_runtime.brokered_repair import (  # noqa: E402
    BrokeredCIRepairRuntime,
    build_docker_brokered_ci_repair_runtime,
    compose_brokered_ci_repair_runtime,
)
from factory_runtime.detector import BaseImagePolicy, DetectionResult  # noqa: E402
from factory_runtime.diagnostics import RuntimeDiagnostics  # noqa: E402
from factory_runtime.docker_provisioner import DockerProvisioningPolicy  # noqa: E402
from factory_runtime.docker_sandbox import workspace_tree_digest  # noqa: E402
from factory_runtime.environment import (  # noqa: E402
    EnvironmentSpec,
    ProvisioningReceipt,
    ProvisioningRequest,
    validate_provisioning_receipt,
)
from factory_runtime.pipeline import RuntimeInvocation, RuntimeObservation  # noqa: E402
from factory_runtime.provider_broker import (  # noqa: E402
    BrokerHTTPResponse,
    EphemeralBrokerCredential,
    ProviderBrokerBudget,
)
from factory_runtime.repair import (  # noqa: E402
    DockerRuntimePipelineFactory,
    RepairPolicy,
    RepairRequest,
    VerifiedRepairCandidate,
)
from factory_runtime.sandbox import SandboxReceipt, SandboxRequest, bind_sandbox_receipt  # noqa: E402
from factory_runtime.structured_repair import StructuredRepairPolicy  # noqa: E402


BASE_IMAGE = "python@sha256:" + "a" * 64
RESULT_IMAGE = "sha256:" + "b" * 64
ENV_DIGEST = "sha256:" + "c" * 64
LOG_DIGEST = "sha256:" + "d" * 64
OUT_DIGEST = "sha256:" + "e" * 64
ERR_DIGEST = "sha256:" + "f" * 64
COMMIT = "1" * 40


class FakeCredentialSource:
    async def issue(self, *, audience: str) -> EphemeralBrokerCredential:
        now = datetime.now(timezone.utc)
        return EphemeralBrokerCredential(
            token="factory-broker-ephemeral-token-123456",
            audience=audience,
            issued_at=now - timedelta(seconds=1),
            expires_at=now + timedelta(minutes=5),
        )


class ScriptedBrokerTransport:
    def __init__(self) -> None:
        self.calls: list[dict] = []
        self.decisions = [
            {"type": "read_files", "paths": ["app.py"]},
            {
                "type": "apply_edits",
                "summary": "fix expected return value",
                "edits": [
                    {
                        "path": "app.py",
                        "old_text": "return 1",
                        "new_text": "return 2",
                    }
                ],
            },
        ]

    async def post_json(self, *, endpoint, headers, body, timeout_seconds):
        payload = json.loads(body.decode("utf-8"))
        self.calls.append(
            {
                "endpoint": endpoint,
                "headers": dict(headers),
                "payload": payload,
                "timeout_seconds": timeout_seconds,
            }
        )
        if not self.decisions:
            raise AssertionError("unexpected extra provider-broker call")
        response = {
            "protocol_version": "factory-repair-broker-v1",
            "request_id": payload["request_id"],
            "binding_digest": payload["binding_digest"],
            "provider_profile": payload["provider_profile"],
            "provider_family": payload["provider_family"],
            "model_selector": payload["model_selector"],
            "decision": self.decisions.pop(0),
            "usage": {
                "input_tokens": 100,
                "output_tokens": 25,
                "cost_usd": "0.01",
            },
        }
        return BrokerHTTPResponse(status_code=200, body=json.dumps(response).encode("utf-8"))


class UnusedTransport:
    async def post_json(self, *, endpoint, headers, body, timeout_seconds):
        raise AssertionError("transport should not be called during composition")


def make_observation(
    workspace: Path,
    invocation: RuntimeInvocation,
    *,
    exit_code: int,
) -> RuntimeObservation:
    now = datetime.now(timezone.utc)
    digest = workspace_tree_digest(workspace)
    spec = EnvironmentSpec(
        stack="python",
        base_image_ref=BASE_IMAGE,
        inputs=(),
        steps=(),
        network_policy_id=None,
    )
    provision_request = ProvisioningRequest(
        request_id=invocation.provisioning_request_id,
        task_id=invocation.task_id,
        lease_id=invocation.lease_id,
        role_id=invocation.role_id,
        source_commit=invocation.source_commit,
        workspace_digest=digest,
        environment_spec_digest=spec.digest,
        max_seconds=invocation.provisioning_timeout_seconds,
        expected_provisioner_identity=invocation.expected_provisioner_identity,
    )
    provision_receipt = ProvisioningReceipt(
        request_id=provision_request.request_id,
        task_id=provision_request.task_id,
        lease_id=provision_request.lease_id,
        role_id=provision_request.role_id,
        source_commit=provision_request.source_commit,
        workspace_digest=provision_request.workspace_digest,
        environment_spec_digest=provision_request.environment_spec_digest,
        provisioner_identity=provision_request.expected_provisioner_identity,
        result_image_ref=RESULT_IMAGE,
        started_at=now - timedelta(seconds=3),
        finished_at=now - timedelta(seconds=2),
        exit_code=0,
        timed_out=False,
        build_log_digest=LOG_DIGEST,
    )
    validated_provisioning = validate_provisioning_receipt(
        provision_request,
        spec,
        provision_receipt,
        now=now,
    )
    verify_request = SandboxRequest(
        request_id=invocation.verification_request_id,
        task_id=invocation.task_id,
        lease_id=invocation.lease_id,
        role_id=invocation.role_id,
        source_commit=invocation.source_commit,
        workspace_digest=digest,
        command=invocation.command,
        environment_digest=ENV_DIGEST,
        timeout_seconds=invocation.verification_timeout_seconds,
        expected_runner_identity=invocation.expected_runner_identity,
    )
    verify_receipt = SandboxReceipt(
        request_id=verify_request.request_id,
        task_id=verify_request.task_id,
        lease_id=verify_request.lease_id,
        role_id=verify_request.role_id,
        source_commit=verify_request.source_commit,
        workspace_digest=verify_request.workspace_digest,
        command_digest=verify_request.command_digest,
        environment_digest=verify_request.environment_digest,
        runner_identity=verify_request.expected_runner_identity,
        sandbox_id="sandbox-brokered-repair",
        started_at=now - timedelta(seconds=2),
        finished_at=now - timedelta(seconds=1),
        exit_code=exit_code,
        timed_out=False,
        stdout_digest=OUT_DIGEST,
        stderr_digest=ERR_DIGEST,
    )
    diagnostics = RuntimeDiagnostics(
        request_digest=verify_request.request_digest,
        stdout_digest=OUT_DIGEST,
        stderr_digest=ERR_DIGEST,
        stdout_excerpt="1 failed" if exit_code else "1 passed",
        stderr_excerpt="AssertionError: expected 2, got 1" if exit_code else "",
        redaction_count=0,
        stdout_truncated=False,
        stderr_truncated=False,
    )
    return RuntimeObservation(
        detection=DetectionResult(spec=spec, stack="python", runtime_version="3.12"),
        provisioning=validated_provisioning,
        verification_request=verify_request,
        verification=bind_sandbox_receipt(verify_request, verify_receipt, now=now),
        workspace_digest=digest,
        diagnostics=diagnostics,
    )


class FakePipeline:
    def __init__(self, workspace: Path, owner: "FakePipelineFactory") -> None:
        self.workspace = workspace
        self.owner = owner

    async def observe(self, invocation: RuntimeInvocation) -> RuntimeObservation:
        self.owner.invocations.append(invocation)
        content = (self.workspace / "app.py").read_text(encoding="utf-8")
        return make_observation(
            self.workspace,
            invocation,
            exit_code=0 if "return 2" in content else 1,
        )


class FakePipelineFactory:
    def __init__(self) -> None:
        self.invocations: list[RuntimeInvocation] = []

    def create(self, workspace: Path) -> FakePipeline:
        return FakePipeline(workspace, self)


def repair_request() -> RepairRequest:
    return RepairRequest(
        repair_id="repair-brokered-1",
        task_id="task-1",
        lease_id="lease-1",
        role_id="engineering_agent",
        source_commit=COMMIT,
        command=("python", "-m", "pytest", "-q"),
        expected_provisioner_identity="fake_provisioner_v1",
        expected_runner_identity="fake_verifier_v1",
        provisioning_timeout_seconds=120,
        verification_timeout_seconds=120,
    )


def broker_budget() -> ProviderBrokerBudget:
    return ProviderBrokerBudget(
        max_cost_usd_per_call=Decimal("0.10"),
        max_total_cost_usd=Decimal("0.25"),
    )


class BrokeredCIRepairRuntimeTests(unittest.TestCase):
    def test_end_to_end_brokered_repair_changes_only_verified_candidate(self):
        factory_root = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as temp:
            authoritative = Path(temp) / "target"
            authoritative.mkdir()
            (authoritative / "app.py").write_text(
                "def value():\n    return 1\n",
                encoding="utf-8",
            )
            runtime_factory = FakePipelineFactory()
            transport = ScriptedBrokerTransport()
            runtime = compose_brokered_ci_repair_runtime(
                factory_root,
                authoritative,
                runtime_factory,
                FakeCredentialSource(),
                transport,
                broker_budget(),
                structured_policy=StructuredRepairPolicy(max_model_turns=3),
                repair_policy=RepairPolicy(max_attempts=2),
            )

            outcome = asyncio.run(runtime.repair(repair_request()))

            self.assertIsInstance(outcome, VerifiedRepairCandidate)
            assert isinstance(outcome, VerifiedRepairCandidate)
            self.assertEqual(
                (authoritative / "app.py").read_text(encoding="utf-8"),
                "def value():\n    return 1\n",
            )
            self.assertEqual(
                (outcome.workspace / "app.py").read_text(encoding="utf-8"),
                "def value():\n    return 2\n",
            )
            self.assertEqual(outcome.verification.receipt.exit_code, 0)
            self.assertEqual(outcome.attempt_number, 1)
            self.assertEqual(len(outcome.actions), 1)
            self.assertEqual(outcome.actions[0].summary, "fix expected return value")
            self.assertEqual(runtime.spent_usd, Decimal("0.02"))
            self.assertEqual(len(runtime.provider_calls), 2)
            self.assertEqual(len(transport.calls), 2)
            self.assertEqual(transport.calls[0]["payload"]["provider_profile"], "coding_primary")
            self.assertEqual(
                transport.calls[0]["payload"]["model_selector"],
                "FACTORY_CODING_MODEL",
            )
            self.assertTrue(
                all(item.command == repair_request().command for item in runtime_factory.invocations)
            )
            self.assertEqual(
                [item.run_id for item in runtime_factory.invocations],
                ["repair-brokered-1.initial", "repair-brokered-1.attempt-1"],
            )
            outcome.cleanup()

    def test_composition_uses_factory_control_repo_binding(self):
        factory_root = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as temp:
            target = Path(temp)
            (target / "app.py").write_text("x = 1\n", encoding="utf-8")
            runtime = compose_brokered_ci_repair_runtime(
                factory_root,
                target,
                FakePipelineFactory(),
                FakeCredentialSource(),
                UnusedTransport(),
                broker_budget(),
            )
            self.assertIsInstance(runtime, BrokeredCIRepairRuntime)
            self.assertEqual(runtime.binding.provider_profile, "coding_primary")
            self.assertEqual(runtime.binding.model_selector, "FACTORY_CODING_MODEL")
            self.assertEqual(runtime.binding.network_policy, "provider_restricted")
            self.assertEqual(runtime.spent_usd, Decimal("0"))

    def test_concrete_docker_builder_wires_existing_runtime_factory(self):
        factory_root = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as temp:
            target = Path(temp)
            (target / "app.py").write_text("x = 1\n", encoding="utf-8")
            runtime = build_docker_brokered_ci_repair_runtime(
                factory_root,
                target,
                BaseImagePolicy(
                    images=(("python:3.12", BASE_IMAGE),),
                    network_policy_id="package-registry-v1",
                ),
                DockerProvisioningPolicy(
                    network_bindings=(("package-registry-v1", "factory-egress"),),
                ),
                FakeCredentialSource(),
                UnusedTransport(),
                broker_budget(),
            )
            self.assertIsInstance(runtime.controller.pipeline_factory, DockerRuntimePipelineFactory)
            self.assertEqual(runtime.provider_calls, ())


if __name__ == "__main__":
    unittest.main()
