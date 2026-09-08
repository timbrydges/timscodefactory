from __future__ import annotations

import asyncio
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from factory_runtime.detector import BaseImagePolicy, EnvironmentDetectionError  # noqa: E402
from factory_runtime.environment import (  # noqa: E402
    EnvironmentSpec,
    ProvisioningContractError,
    ProvisioningReceipt,
    ProvisioningRequest,
)
from factory_runtime.pipeline import (  # noqa: E402
    RuntimeInvocation,
    RuntimePipeline,
    RuntimePipelineError,
    VerificationBinding,
)
from factory_runtime.sandbox import SandboxContractError, SandboxReceipt, SandboxRequest  # noqa: E402


BASE_IMAGE = "python@sha256:" + "a" * 64
RESULT_IMAGE = "sha256:" + "b" * 64
LOG_DIGEST = "sha256:" + "c" * 64
OUT_DIGEST = "sha256:" + "d" * 64
ERR_DIGEST = "sha256:" + "e" * 64
COMMIT = "f" * 40
ENV_DIGEST = "sha256:" + "1" * 64


def write_python_workspace(root: Path) -> None:
    (root / "pyproject.toml").write_text(
        '[project]\nname="demo"\nrequires-python=">=3.12"\ndependencies=[]\n',
        encoding="utf-8",
    )
    (root / "requirements-ci.txt").write_text(
        "jsonschema==4.26.0 \\\n"
        "    --hash=sha256:" + "2" * 64 + "\n",
        encoding="utf-8",
    )
    tests = root / "tests"
    tests.mkdir()
    (tests / "test_demo.py").write_text("assert True\n", encoding="utf-8")


def image_policy() -> BaseImagePolicy:
    return BaseImagePolicy(
        images=(("python:3.12", BASE_IMAGE),),
        network_policy_id="package-registry-v1",
    )


def invocation() -> RuntimeInvocation:
    return RuntimeInvocation(
        run_id="run-1",
        task_id="task-1",
        lease_id="lease-1",
        role_id="engineering_agent",
        source_commit=COMMIT,
        command=("python", "-m", "unittest", "discover", "-s", "tests"),
        expected_provisioner_identity="fake_provisioner_v1",
        expected_runner_identity="fake_verifier_v1",
        provisioning_timeout_seconds=300,
        verification_timeout_seconds=120,
    )


class FakeProvisioner:
    def __init__(self, workspace: Path, *, exit_code: int = 0, mutate: bool = False) -> None:
        self.workspace = workspace
        self.exit_code = exit_code
        self.mutate = mutate
        self.calls: list[tuple[ProvisioningRequest, EnvironmentSpec]] = []

    async def provision(
        self,
        request: ProvisioningRequest,
        spec: EnvironmentSpec,
    ) -> ProvisioningReceipt:
        self.calls.append((request, spec))
        now = datetime.now(timezone.utc)
        if self.mutate:
            (self.workspace / "changed-after-detection.txt").write_text("mutation\n", encoding="utf-8")
        return ProvisioningReceipt(
            request_id=request.request_id,
            task_id=request.task_id,
            lease_id=request.lease_id,
            role_id=request.role_id,
            source_commit=request.source_commit,
            workspace_digest=request.workspace_digest,
            environment_spec_digest=request.environment_spec_digest,
            provisioner_identity=request.expected_provisioner_identity,
            result_image_ref=RESULT_IMAGE if self.exit_code == 0 else None,
            started_at=now - timedelta(seconds=2),
            finished_at=now - timedelta(seconds=1),
            exit_code=self.exit_code,
            timed_out=False,
            build_log_digest=LOG_DIGEST,
        )


class FakeSandbox:
    def __init__(self, *, exit_code: int = 0) -> None:
        self.exit_code = exit_code
        self.calls: list[SandboxRequest] = []

    async def execute(self, request: SandboxRequest) -> SandboxReceipt:
        self.calls.append(request)
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
            sandbox_id="sandbox-1",
            started_at=now - timedelta(seconds=2),
            finished_at=now - timedelta(seconds=1),
            exit_code=self.exit_code,
            timed_out=False,
            stdout_digest=OUT_DIGEST,
            stderr_digest=ERR_DIGEST,
        )


class FakeVerificationFactory:
    def __init__(self, sandbox: FakeSandbox, *, runner_identity: str = "fake_verifier_v1") -> None:
        self.sandbox = sandbox
        self.runner_identity = runner_identity
        self.images: list[str] = []

    def create(
        self,
        *,
        workspace: Path,
        image_ref: str,
        expected_runner_identity: str,
    ) -> VerificationBinding:
        self.images.append(image_ref)
        return VerificationBinding(
            adapter=self.sandbox,
            environment_digest=ENV_DIGEST,
            runner_identity=self.runner_identity,
        )


class RuntimePipelineTests(unittest.TestCase):
    def test_happy_path_composes_detection_provisioning_and_verification(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_python_workspace(root)
            provisioner = FakeProvisioner(root)
            sandbox = FakeSandbox()
            factory = FakeVerificationFactory(sandbox)
            pipeline = RuntimePipeline(root, image_policy(), provisioner, factory)

            result = asyncio.run(pipeline.run(invocation()))

            self.assertEqual(result.detection.stack, "python")
            self.assertEqual(result.detection.runtime_version, "3.12")
            self.assertEqual(result.provisioning.receipt.result_image_ref, RESULT_IMAGE)
            self.assertEqual(factory.images, [RESULT_IMAGE])
            self.assertEqual(len(sandbox.calls), 1)
            verify_request = sandbox.calls[0]
            self.assertEqual(verify_request.command, invocation().command)
            self.assertEqual(verify_request.task_id, invocation().task_id)
            self.assertEqual(verify_request.lease_id, invocation().lease_id)
            self.assertEqual(result.verification.receipt.exit_code, 0)
            self.assertFalse(hasattr(result, "signature_valid"))
            self.assertFalse(hasattr(result, "producer_identity"))
            self.assertFalse(hasattr(result, "transition"))

    def test_subrequest_ids_are_derived_from_one_runtime_run_id(self):
        inv = invocation()
        self.assertEqual(inv.provisioning_request_id, "run-1.provision")
        self.assertEqual(inv.verification_request_id, "run-1.verify")

    def test_overlong_run_id_is_denied(self):
        with self.assertRaises(RuntimePipelineError):
            RuntimeInvocation(
                run_id="r" * 97,
                task_id="task-1",
                lease_id="lease-1",
                role_id="engineering_agent",
                source_commit=COMMIT,
                command=("python", "-V"),
                expected_provisioner_identity="fake_provisioner_v1",
                expected_runner_identity="fake_verifier_v1",
            )

    def test_failed_provisioning_never_reaches_verification(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_python_workspace(root)
            provisioner = FakeProvisioner(root, exit_code=7)
            sandbox = FakeSandbox()
            factory = FakeVerificationFactory(sandbox)
            pipeline = RuntimePipeline(root, image_policy(), provisioner, factory)

            with self.assertRaises(ProvisioningContractError):
                asyncio.run(pipeline.run(invocation()))
            self.assertEqual(factory.images, [])
            self.assertEqual(sandbox.calls, [])

    def test_workspace_mutation_during_provisioning_fails_before_verification(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_python_workspace(root)
            provisioner = FakeProvisioner(root, mutate=True)
            sandbox = FakeSandbox()
            factory = FakeVerificationFactory(sandbox)
            pipeline = RuntimePipeline(root, image_policy(), provisioner, factory)

            with self.assertRaises(RuntimePipelineError):
                asyncio.run(pipeline.run(invocation()))
            self.assertEqual(factory.images, [])
            self.assertEqual(sandbox.calls, [])

    def test_wrong_verification_runner_binding_is_denied(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_python_workspace(root)
            provisioner = FakeProvisioner(root)
            sandbox = FakeSandbox()
            factory = FakeVerificationFactory(sandbox, runner_identity="wrong_runner")
            pipeline = RuntimePipeline(root, image_policy(), provisioner, factory)

            with self.assertRaises(RuntimePipelineError):
                asyncio.run(pipeline.run(invocation()))
            self.assertEqual(sandbox.calls, [])

    def test_nonzero_verification_receipt_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_python_workspace(root)
            pipeline = RuntimePipeline(
                root,
                image_policy(),
                FakeProvisioner(root),
                FakeVerificationFactory(FakeSandbox(exit_code=5)),
            )
            with self.assertRaises(SandboxContractError):
                asyncio.run(pipeline.run(invocation()))

    def test_unsupported_stack_fails_before_provisioning(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "go.mod").write_text("module example.com/demo\n", encoding="utf-8")
            provisioner = FakeProvisioner(root)
            pipeline = RuntimePipeline(
                root,
                image_policy(),
                provisioner,
                FakeVerificationFactory(FakeSandbox()),
            )
            with self.assertRaises(EnvironmentDetectionError):
                asyncio.run(pipeline.run(invocation()))
            self.assertEqual(provisioner.calls, [])


if __name__ == "__main__":
    unittest.main()
