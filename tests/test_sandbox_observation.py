from __future__ import annotations

import sys
import unittest
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from factory_runtime.sandbox import (  # noqa: E402
    SandboxContractError,
    SandboxReceipt,
    SandboxRequest,
    bind_sandbox_receipt,
    validate_sandbox_receipt,
)


NOW = datetime(2026, 9, 8, 15, 15, 0, tzinfo=timezone.utc)
COMMIT = "a" * 40
WORKSPACE = "sha256:" + "b" * 64
ENV = "sha256:" + "c" * 64
OUT = "sha256:" + "d" * 64
ERR = "sha256:" + "e" * 64


def request() -> SandboxRequest:
    return SandboxRequest(
        request_id="observe-1",
        task_id="task-1",
        lease_id="lease-1",
        role_id="engineering_agent",
        source_commit=COMMIT,
        workspace_digest=WORKSPACE,
        command=("python", "-m", "pytest", "-q"),
        environment_digest=ENV,
        timeout_seconds=120,
        expected_runner_identity="factory_docker_sandbox_v1",
    )


def receipt(*, exit_code: int | None = 1, timed_out: bool = False) -> SandboxReceipt:
    req = request()
    return SandboxReceipt(
        request_id=req.request_id,
        task_id=req.task_id,
        lease_id=req.lease_id,
        role_id=req.role_id,
        source_commit=req.source_commit,
        workspace_digest=req.workspace_digest,
        command_digest=req.command_digest,
        environment_digest=req.environment_digest,
        runner_identity=req.expected_runner_identity,
        sandbox_id="sandbox-1",
        started_at=NOW - timedelta(seconds=10),
        finished_at=NOW - timedelta(seconds=1),
        exit_code=exit_code,
        timed_out=timed_out,
        stdout_digest=OUT,
        stderr_digest=ERR,
    )


class SandboxObservationTests(unittest.TestCase):
    def test_nonzero_exit_is_trusted_as_bound_observation_not_success(self):
        req = request()
        observed = bind_sandbox_receipt(req, receipt(exit_code=7), now=NOW)
        self.assertEqual(observed.receipt.exit_code, 7)
        self.assertEqual(observed.request_digest, req.request_digest)
        self.assertFalse(hasattr(observed, "signature_valid"))
        with self.assertRaises(SandboxContractError):
            validate_sandbox_receipt(req, observed.receipt, now=NOW)

    def test_timeout_is_trusted_as_bound_observation_not_success(self):
        req = request()
        observed = bind_sandbox_receipt(
            req,
            receipt(exit_code=None, timed_out=True),
            now=NOW,
        )
        self.assertTrue(observed.receipt.timed_out)
        with self.assertRaises(SandboxContractError):
            validate_sandbox_receipt(req, observed.receipt, now=NOW)

    def test_successful_observation_can_be_promoted_only_to_runtime_verification(self):
        req = request()
        success = receipt(exit_code=0)
        observed = bind_sandbox_receipt(req, success, now=NOW)
        validated = validate_sandbox_receipt(req, success, now=NOW)
        self.assertEqual(observed.request_digest, validated.request_digest)
        self.assertEqual(validated.receipt.exit_code, 0)
        self.assertFalse(hasattr(validated, "producer_identity"))

    def test_wrong_command_binding_cannot_be_observed(self):
        req = request()
        wrong = replace(receipt(), command_digest="sha256:" + "f" * 64)
        with self.assertRaises(SandboxContractError):
            bind_sandbox_receipt(req, wrong, now=NOW)

    def test_wrong_workspace_binding_cannot_be_observed(self):
        req = request()
        wrong = replace(receipt(), workspace_digest="sha256:" + "f" * 64)
        with self.assertRaises(SandboxContractError):
            bind_sandbox_receipt(req, wrong, now=NOW)

    def test_wrong_runner_binding_cannot_be_observed(self):
        req = request()
        wrong = replace(receipt(), runner_identity="unexpected_runner")
        with self.assertRaises(SandboxContractError):
            bind_sandbox_receipt(req, wrong, now=NOW)

    def test_future_receipt_cannot_be_observed(self):
        req = request()
        future = replace(
            receipt(),
            started_at=NOW + timedelta(seconds=1),
            finished_at=NOW + timedelta(seconds=2),
        )
        with self.assertRaises(SandboxContractError):
            bind_sandbox_receipt(req, future, now=NOW)

    def test_overlong_execution_cannot_be_observed_as_bound(self):
        req = replace(request(), timeout_seconds=5)
        slow = replace(
            receipt(),
            started_at=NOW - timedelta(seconds=10),
            finished_at=NOW - timedelta(seconds=1),
        )
        with self.assertRaises(SandboxContractError):
            bind_sandbox_receipt(req, slow, now=NOW)

    def test_timeout_with_exit_code_is_internally_inconsistent(self):
        req = request()
        with self.assertRaises(SandboxContractError):
            bind_sandbox_receipt(
                req,
                receipt(exit_code=137, timed_out=True),
                now=NOW,
            )

    def test_completed_receipt_without_exit_code_is_internally_inconsistent(self):
        req = request()
        with self.assertRaises(SandboxContractError):
            bind_sandbox_receipt(
                req,
                receipt(exit_code=None, timed_out=False),
                now=NOW,
            )


if __name__ == "__main__":
    unittest.main()
