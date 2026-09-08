from __future__ import annotations

import asyncio
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from factory_runtime.detector import BaseImagePolicy  # noqa: E402
from factory_runtime.environment import EnvironmentSpec, ProvisioningReceipt, ProvisioningRequest  # noqa: E402
from factory_runtime.pipeline import RuntimeInvocation, RuntimePipeline, VerificationBinding  # noqa: E402
from factory_runtime.sandbox import SandboxContractError, SandboxReceipt, SandboxRequest  # noqa: E402


BASE_IMAGE = "python@sha256:" + "a" * 64
RESULT_IMAGE = "sha256:" + "b" * 64
LOG_DIGEST = "sha256:" + "c" * 64
OUT_DIGEST = "sha256:" + "d" * 64
ERR_DIGEST = "sha256:" + "e" * 64
ENV_DIGEST = "sha256:" + "1" * 64
COMMIT = "f" * 40


def write_workspace(root: Path) -> None:
    (root / "pyproject.toml").write_text(
        '[project]\nname="demo"\nrequires-python=">=3.12"\ndependencies=[]\n',
        encoding="utf-8",
    )
    (root / "requirements-ci.txt").write_text(
        "jsonschema==4.26.0 \\\n"
        "    --hash=sha256:" + "2" * 64 + "\n",
        encoding="utf-8",
    )


def image_policy() -> BaseImagePolicy:
    return BaseImagePolicy(
        images=(("python:3.12", BASE_IMAGE),),
        network_policy_id="package-registry-v1",
    )


def invocation() -> RuntimeInvocation:
    return RuntimeInvocation(
        run_id="observe-run-1",
        task_id="task-1",
        lease_id="lease-1",
        role_id="engineering_agent",
        source_commit=COMMIT,
        command=("python", "-m", "pytest", "-q"),
        expected_provisioner_identity="fake_provisioner_v1",
        expected_runner_identity="fake_verifier_v1",
    )


class FakeProvisioner:
    async def provision(self, request: ProvisioningRequest, spec: EnvironmentSpec) -> ProvisioningReceipt:
        now = datetime.now(timezone.utc)
        return ProvisioningReceipt(
            request_id=request.request_id,
            task_id=request.task_id,
            lease_id=request.lease_id,
            role_id=request.role_id,
            source_commit=request.source_commit,
            workspace_digest=request.workspace_digest,
            environment_spec_digest=request.environment_spec_digest,
            provisioner_identity=request.expected_provisioner_identity,
            result_image_ref=RESULT_IMAGE,
            started_at=now - timedelta(seconds=2),
            finished_at=now - timedelta(seconds=1),
            exit_code=0,
            timed_out=False,
            build_log_digest=LOG_DIGEST,
        )


class FakeSandbox:
    def __init__(self, *, exit_code: int | None, timed_out: bool = False) -> None:
        self.exit_code = exit_code
        self.timed_out = timed_out

    async def execute(self, request: SandboxRequest) -> SandboxReceipt:
        now = datetime.now(timezone.utc)
        return SandboxReceipt(
            request_id=request.request_id,
            task_id=request.task_id,
            lease_id=request.lease_id,
            role_id=request.role_id,
            source_commit=request.source_commit,
            workspace_digest=request.workspace_digest,
            command_digest=request.command_digest,
            environment_digest=request.environment_digest,
            runner_identity=request.expected_runner_identity,
            sandbox_id="sandbox-observe-1",
            started_at=now - timedelta(seconds=2),
            finished_at=now - timedelta(seconds=1),
            exit_code=self.exit_code,
            timed_out=self.timed_out,
            stdout_digest=OUT_DIGEST,
            stderr_digest=ERR_DIGEST,
        )


class FakeVerificationFactory:
    def __init__(self, sandbox: FakeSandbox) -> None:
        self.sandbox = sandbox

    def create(self, *, workspace: Path, image_ref: str, expected_runner_identity: str) -> VerificationBinding:
        return VerificationBinding(
            adapter=self.sandbox,
            environment_digest=ENV_DIGEST,
            runner_identity=expected_runner_identity,
        )


def pipeline(root: Path, sandbox: FakeSandbox) -> RuntimePipeline:
    return RuntimePipeline(
        root,
        image_policy(),
        FakeProvisioner(),
        FakeVerificationFactory(sandbox),
    )


class RuntimeObservationPipelineTests(unittest.TestCase):
    def test_nonzero_exit_can_be_observed_without_becoming_success(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_workspace(root)
            observed = asyncio.run(pipeline(root, FakeSandbox(exit_code=7)).observe(invocation()))
            self.assertEqual(observed.verification.receipt.exit_code, 7)
            self.assertFalse(observed.verification.receipt.timed_out)
            self.assertFalse(hasattr(observed, "signature_valid"))

    def test_run_still_rejects_nonzero_observation(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_workspace(root)
            with self.assertRaises(SandboxContractError):
                asyncio.run(pipeline(root, FakeSandbox(exit_code=7)).run(invocation()))

    def test_timeout_can_be_observed_but_not_verified(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_workspace(root)
            p = pipeline(root, FakeSandbox(exit_code=None, timed_out=True))
            observed = asyncio.run(p.observe(invocation()))
            self.assertTrue(observed.verification.receipt.timed_out)
            with self.assertRaises(SandboxContractError):
                asyncio.run(p.run(invocation()))

    def test_successful_observation_still_promotes_through_run(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_workspace(root)
            result = asyncio.run(pipeline(root, FakeSandbox(exit_code=0)).run(invocation()))
            self.assertEqual(result.verification.receipt.exit_code, 0)
            self.assertFalse(hasattr(result, "producer_identity"))


if __name__ == "__main__":
    unittest.main()
