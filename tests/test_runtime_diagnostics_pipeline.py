from __future__ import annotations

import asyncio
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from factory_runtime.detector import BaseImagePolicy  # noqa: E402
from factory_runtime.diagnostics import RuntimeDiagnostics  # noqa: E402
from factory_runtime.environment import ProvisioningReceipt  # noqa: E402
from factory_runtime.pipeline import (  # noqa: E402
    RuntimeInvocation,
    RuntimePipeline,
    VerificationBinding,
)
from factory_runtime.sandbox import SandboxReceipt  # noqa: E402


BASE_IMAGE = "python@sha256:" + "a" * 64
RESULT_IMAGE = "sha256:" + "b" * 64
COMMIT = "c" * 40
OUTPUT_DIGEST = "sha256:" + "d" * 64
ERROR_DIGEST = "sha256:" + "e" * 64
LOG_DIGEST = "sha256:" + "f" * 64
ENVIRONMENT_DIGEST = "sha256:" + "1" * 64


class FakeProvisioner:
    async def provision(self, request, spec):
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
            started_at=now - timedelta(seconds=1),
            finished_at=now,
            exit_code=0,
            timed_out=False,
            build_log_digest=LOG_DIGEST,
        )


class FakeAdapter:
    async def execute(self, request):
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
            sandbox_id="diag-sandbox",
            started_at=now - timedelta(seconds=1),
            finished_at=now,
            exit_code=1,
            timed_out=False,
            stdout_digest=OUTPUT_DIGEST,
            stderr_digest=ERROR_DIGEST,
        )


class FakeDiagnosticSource:
    def take(self, request, receipt):
        return RuntimeDiagnostics(
            request_digest=request.request_digest,
            stdout_digest=receipt.stdout_digest,
            stderr_digest=receipt.stderr_digest,
            stdout_excerpt="1 failed, 9 passed",
            stderr_excerpt="AssertionError: expected 2, got 1",
            redaction_count=1,
            stdout_truncated=False,
            stderr_truncated=False,
        )


class FakeVerificationFactory:
    def create(self, *, workspace, image_ref, expected_runner_identity):
        return VerificationBinding(
            adapter=FakeAdapter(),
            environment_digest=ENVIRONMENT_DIGEST,
            runner_identity=expected_runner_identity,
            diagnostic_source=FakeDiagnosticSource(),
        )


class RuntimeDiagnosticsPipelineTests(unittest.TestCase):
    def test_failure_observation_surfaces_non_authoritative_diagnostics(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "pyproject.toml").write_text(
                '[project]\nname="demo"\nrequires-python=">=3.12"\ndependencies=[]\n',
                encoding="utf-8",
            )
            (root / "requirements-ci.txt").write_text(
                "demo==1.0.0 \\\n"
                "    --hash=sha256:" + "2" * 64 + "\n",
                encoding="utf-8",
            )
            pipeline = RuntimePipeline(
                root,
                BaseImagePolicy(
                    images=(("python:3.12", BASE_IMAGE),),
                    network_policy_id="package-registry-v1",
                ),
                FakeProvisioner(),
                FakeVerificationFactory(),
            )
            invocation = RuntimeInvocation(
                run_id="diag-run",
                task_id="task-1",
                lease_id="lease-1",
                role_id="engineering_agent",
                source_commit=COMMIT,
                command=("python", "-m", "pytest"),
                expected_provisioner_identity="fake_provisioner_v1",
                expected_runner_identity="fake_runner_v1",
            )

            observed = asyncio.run(pipeline.observe(invocation))

            self.assertEqual(observed.verification.receipt.exit_code, 1)
            self.assertIsNotNone(observed.diagnostics)
            assert observed.diagnostics is not None
            self.assertIn("AssertionError", observed.diagnostics.stderr_excerpt)
            self.assertEqual(
                observed.diagnostics.request_digest,
                observed.verification_request.request_digest,
            )
            self.assertFalse(hasattr(observed.diagnostics, "signature_valid"))
            self.assertFalse(hasattr(observed.diagnostics, "producer_identity"))


if __name__ == "__main__":
    unittest.main()
