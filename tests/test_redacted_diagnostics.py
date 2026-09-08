from __future__ import annotations

import asyncio
import hashlib
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from factory_runtime.diagnostics import (  # noqa: E402
    DiagnosticCaptureError,
    RedactedDiagnosticCapture,
)
from factory_runtime.docker_sandbox import (  # noqa: E402
    DockerSandboxAdapter,
    DockerSandboxPolicy,
    ProcessResult,
    workspace_tree_digest,
)
from factory_runtime.sandbox import SandboxReceipt, SandboxRequest  # noqa: E402


NOW = datetime(2026, 9, 8, 16, 0, 0, tzinfo=timezone.utc)
IMAGE = "python@sha256:" + "a" * 64
COMMIT = "b" * 40
CONTAINER_ID = "c" * 64


def digest(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def request(*, workspace_digest: str = "sha256:" + "d" * 64, environment_digest: str = "sha256:" + "e" * 64) -> SandboxRequest:
    return SandboxRequest(
        request_id="diag-request-1",
        task_id="task-1",
        lease_id="lease-1",
        role_id="engineering_agent",
        source_commit=COMMIT,
        workspace_digest=workspace_digest,
        command=("python", "-m", "pytest"),
        environment_digest=environment_digest,
        timeout_seconds=120,
        expected_runner_identity="factory_docker_sandbox_v1",
    )


def receipt(req: SandboxRequest, stdout: bytes, stderr: bytes, *, exit_code: int = 1) -> SandboxReceipt:
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
        started_at=NOW - timedelta(seconds=2),
        finished_at=NOW - timedelta(seconds=1),
        exit_code=exit_code,
        timed_out=False,
        stdout_digest=digest(stdout),
        stderr_digest=digest(stderr),
    )


class FakeRunner:
    def __init__(self, *responses: ProcessResult) -> None:
        self.responses = list(responses)

    async def run(self, argv: tuple[str, ...], *, timeout_seconds: int) -> ProcessResult:
        if not self.responses:
            raise AssertionError(f"unexpected process call: {argv}")
        return self.responses.pop(0)


class RedactedDiagnosticsTests(unittest.TestCase):
    def test_redacts_common_secret_forms_and_never_exposes_raw_fields(self):
        gh_token = "ghp_" + "A" * 32
        api_key = "sk-" + "B" * 24
        jwt = "eyJabcdefgh.ijklmnopqrst.uvwxyzABCDE"
        aws_key = "AKIA" + "C" * 16
        stdout = (
            f"password=hunter2\nAuthorization: Bearer abcdefghijklmnop\n"
            f"github={gh_token}\napi_key={api_key}\naws={aws_key}\njwt={jwt}\n"
            "-----BEGIN PRIVATE KEY-----\nvery-secret-key-material\n-----END PRIVATE KEY-----\n"
        ).encode()
        stderr = b"database=postgres://admin:swordfish@example.test/app\n"
        req = request()
        rec = receipt(req, stdout, stderr)
        capture = RedactedDiagnosticCapture()

        capture.capture(req, rec, stdout, stderr)
        item = capture.take(req, rec)
        combined = item.stdout_excerpt + item.stderr_excerpt

        for secret in (
            "hunter2",
            "abcdefghijklmnop",
            gh_token,
            api_key,
            aws_key,
            jwt,
            "very-secret-key-material",
            "swordfish",
        ):
            self.assertNotIn(secret, combined)
        self.assertIn("[REDACTED", combined)
        self.assertGreaterEqual(item.redaction_count, 7)
        self.assertFalse(hasattr(item, "raw_stdout"))
        self.assertFalse(hasattr(item, "raw_stderr"))
        self.assertEqual(item.stdout_digest, rec.stdout_digest)
        self.assertEqual(item.stderr_digest, rec.stderr_digest)

    def test_truncation_is_bounded_and_keeps_failure_tail(self):
        stdout = ("HEAD\n" + "x" * 2000 + "\npassword=tail-secret\nFINAL-ERROR\n").encode()
        stderr = b""
        req = request()
        rec = receipt(req, stdout, stderr)
        capture = RedactedDiagnosticCapture(max_chars_per_stream=512)

        capture.capture(req, rec, stdout, stderr)
        item = capture.take(req, rec)

        self.assertTrue(item.stdout_truncated)
        self.assertLessEqual(len(item.stdout_excerpt), 512)
        self.assertIn("TRUNCATED BY FACTORY DIAGNOSTICS", item.stdout_excerpt)
        self.assertIn("FINAL-ERROR", item.stdout_excerpt)
        self.assertNotIn("tail-secret", item.stdout_excerpt)

    def test_digest_mismatch_fails_closed(self):
        stdout = b"failed\n"
        stderr = b"boom\n"
        req = request()
        rec = receipt(req, stdout, stderr)
        bad = SandboxReceipt(
            **{
                **rec.__dict__,
                "stdout_digest": "sha256:" + "f" * 64,
            }
        )
        with self.assertRaises(DiagnosticCaptureError):
            RedactedDiagnosticCapture().capture(req, bad, stdout, stderr)

    def test_diagnostics_are_one_shot(self):
        stdout = b"failure\n"
        stderr = b""
        req = request()
        rec = receipt(req, stdout, stderr)
        capture = RedactedDiagnosticCapture()
        capture.capture(req, rec, stdout, stderr)
        capture.take(req, rec)
        with self.assertRaises(DiagnosticCaptureError):
            capture.take(req, rec)

    def test_docker_adapter_captures_only_redacted_output(self):
        with tempfile.TemporaryDirectory() as temp:
            workspace = Path(temp) / "repo"
            workspace.mkdir()
            (workspace / "app.py").write_text("print('x')\n", encoding="utf-8")
            policy = DockerSandboxPolicy(image_ref=IMAGE)
            req = request(
                workspace_digest=workspace_tree_digest(workspace),
                environment_digest=policy.environment_digest,
            )
            stdout = b"test failed password=supersecret\n"
            stderr = b"Authorization: Bearer tokenvalue123456\n"
            runner = FakeRunner(
                ProcessResult(0, b"image\n", b""),
                ProcessResult(0, (CONTAINER_ID + "\n").encode(), b""),
                ProcessResult(0, stdout, stderr),
                ProcessResult(0, b"1\n", b""),
                ProcessResult(0, b"", b""),
            )
            capture = RedactedDiagnosticCapture()
            adapter = DockerSandboxAdapter(
                workspace,
                policy,
                process_runner=runner,
                diagnostic_capture=capture,
            )

            rec = asyncio.run(adapter.execute(req))
            item = capture.take(req, rec)

            self.assertNotIn("supersecret", item.stdout_excerpt)
            self.assertNotIn("tokenvalue123456", item.stderr_excerpt)
            self.assertIn("test failed", item.stdout_excerpt)
            self.assertEqual(rec.stdout_digest, digest(stdout))
            self.assertEqual(rec.stderr_digest, digest(stderr))


if __name__ == "__main__":
    unittest.main()
