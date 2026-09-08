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
    command_digest,
    validate_sandbox_receipt,
)


NOW = datetime(2026, 9, 8, 5, 0, 0, tzinfo=timezone.utc)
COMMIT = "a" * 40
WORKSPACE_DIGEST = "sha256:" + "9" * 64
ENV_DIGEST = "sha256:" + "b" * 64
STDOUT_DIGEST = "sha256:" + "c" * 64
STDERR_DIGEST = "sha256:" + "d" * 64


def request() -> SandboxRequest:
    return SandboxRequest(
        request_id="req-1",
        task_id="task-1",
        lease_id="lease-1",
        role_id="engineering_agent",
        source_commit=COMMIT,
        workspace_digest=WORKSPACE_DIGEST,
        command=("python", "-m", "unittest", "discover", "-s", "tests", "-v"),
        environment_digest=ENV_DIGEST,
        timeout_seconds=300,
        expected_runner_identity="factory_sandbox_runner_v1",
    )


def receipt(req: SandboxRequest | None = None) -> SandboxReceipt:
    req = req or request()
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
        sandbox_id="sandbox-123",
        started_at=NOW - timedelta(seconds=10),
        finished_at=NOW - timedelta(seconds=1),
        exit_code=0,
        timed_out=False,
        stdout_digest=STDOUT_DIGEST,
        stderr_digest=STDERR_DIGEST,
    )


class SandboxAdapterContractTests(unittest.TestCase):
    def test_valid_receipt_is_validated_but_not_promoted_to_factory_evidence(self):
        req = request()
        validated = validate_sandbox_receipt(req, receipt(req), now=NOW)
        self.assertEqual(validated.receipt.request_id, req.request_id)
        self.assertEqual(validated.request_digest, req.request_digest)
        self.assertFalse(hasattr(validated, "signature_valid"))
        self.assertFalse(hasattr(validated, "producer_identity"))

    def test_command_digest_is_argv_boundary_safe(self):
        self.assertNotEqual(command_digest(("ab", "c")), command_digest(("a", "bc")))

    def test_empty_command_is_denied(self):
        with self.assertRaises(SandboxContractError):
            replace(request(), command=())

    def test_wrong_task_binding_is_denied(self):
        req = request()
        with self.assertRaises(SandboxContractError):
            validate_sandbox_receipt(req, replace(receipt(req), task_id="task-2"), now=NOW)

    def test_wrong_lease_binding_is_denied(self):
        req = request()
        with self.assertRaises(SandboxContractError):
            validate_sandbox_receipt(req, replace(receipt(req), lease_id="lease-2"), now=NOW)

    def test_wrong_role_binding_is_denied(self):
        req = request()
        with self.assertRaises(SandboxContractError):
            validate_sandbox_receipt(req, replace(receipt(req), role_id="independent_inspector"), now=NOW)

    def test_wrong_commit_binding_is_denied(self):
        req = request()
        with self.assertRaises(SandboxContractError):
            validate_sandbox_receipt(req, replace(receipt(req), source_commit="f" * 40), now=NOW)

    def test_wrong_workspace_binding_is_denied(self):
        req = request()
        with self.assertRaises(SandboxContractError):
            validate_sandbox_receipt(
                req,
                replace(receipt(req), workspace_digest="sha256:" + "8" * 64),
                now=NOW,
            )

    def test_wrong_command_binding_is_denied(self):
        req = request()
        other = command_digest(("pytest", "-q"))
        with self.assertRaises(SandboxContractError):
            validate_sandbox_receipt(req, replace(receipt(req), command_digest=other), now=NOW)

    def test_wrong_environment_binding_is_denied(self):
        req = request()
        with self.assertRaises(SandboxContractError):
            validate_sandbox_receipt(
                req,
                replace(receipt(req), environment_digest="sha256:" + "e" * 64),
                now=NOW,
            )

    def test_wrong_runner_identity_is_denied(self):
        req = request()
        with self.assertRaises(SandboxContractError):
            validate_sandbox_receipt(req, replace(receipt(req), runner_identity="unknown_runner"), now=NOW)

    def test_nonzero_exit_is_denied(self):
        req = request()
        with self.assertRaises(SandboxContractError):
            validate_sandbox_receipt(req, replace(receipt(req), exit_code=1), now=NOW)

    def test_timeout_is_denied(self):
        req = request()
        with self.assertRaises(SandboxContractError):
            validate_sandbox_receipt(req, replace(receipt(req), exit_code=None, timed_out=True), now=NOW)

    def test_elapsed_time_over_authorized_timeout_is_denied(self):
        req = replace(request(), timeout_seconds=5)
        with self.assertRaises(SandboxContractError):
            validate_sandbox_receipt(req, receipt(req), now=NOW)

    def test_future_dated_receipt_is_denied(self):
        req = request()
        future = replace(
            receipt(req),
            started_at=NOW + timedelta(seconds=1),
            finished_at=NOW + timedelta(seconds=2),
        )
        with self.assertRaises(SandboxContractError):
            validate_sandbox_receipt(req, future, now=NOW)

    def test_reversed_timestamps_are_denied(self):
        req = request()
        reversed_receipt = replace(
            receipt(req),
            started_at=NOW - timedelta(seconds=1),
            finished_at=NOW - timedelta(seconds=10),
        )
        with self.assertRaises(SandboxContractError):
            validate_sandbox_receipt(req, reversed_receipt, now=NOW)

    def test_malformed_output_digest_is_denied(self):
        req = request()
        with self.assertRaises(SandboxContractError):
            replace(receipt(req), stdout_digest="not-a-digest")

    def test_request_digest_changes_when_authority_binding_changes(self):
        req = request()
        changed = replace(req, lease_id="lease-2")
        self.assertNotEqual(req.request_digest, changed.request_digest)

    def test_request_digest_changes_when_workspace_changes(self):
        req = request()
        changed = replace(req, workspace_digest="sha256:" + "7" * 64)
        self.assertNotEqual(req.request_digest, changed.request_digest)


if __name__ == "__main__":
    unittest.main()
