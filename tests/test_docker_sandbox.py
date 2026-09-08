from __future__ import annotations

import asyncio
import sys
import tempfile
import unittest
from dataclasses import replace
from datetime import timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from factory_runtime.docker_sandbox import (  # noqa: E402
    DockerSandboxAdapter,
    DockerSandboxPolicy,
    ProcessResult,
    ProcessTimeout,
    SandboxExecutionError,
    workspace_tree_digest,
)
from factory_runtime.sandbox import (  # noqa: E402
    SandboxContractError,
    SandboxRequest,
    validate_sandbox_receipt,
)


IMAGE = "python@sha256:" + "a" * 64
LOCAL_IMAGE = "sha256:" + "d" * 64
COMMIT = "b" * 40
CONTAINER_ID = "c" * 64


class FakeRunner:
    def __init__(self, *responses):
        self.responses = list(responses)
        self.calls: list[tuple[tuple[str, ...], int]] = []

    async def run(self, argv: tuple[str, ...], *, timeout_seconds: int) -> ProcessResult:
        self.calls.append((argv, timeout_seconds))
        if not self.responses:
            raise AssertionError(f"unexpected process call: {argv}")
        response = self.responses.pop(0)
        if isinstance(response, BaseException):
            raise response
        return response


class DockerSandboxTests(unittest.TestCase):
    def _workspace(self, root: str) -> Path:
        workspace = Path(root) / "repo"
        workspace.mkdir()
        (workspace / "app.py").write_text("print('ok')\n", encoding="utf-8")
        tests = workspace / "tests"
        tests.mkdir()
        (tests / "test_app.py").write_text("assert True\n", encoding="utf-8")
        return workspace

    def _request(self, workspace: Path, policy: DockerSandboxPolicy) -> SandboxRequest:
        return SandboxRequest(
            request_id="req-docker-1",
            task_id="task-1",
            lease_id="lease-1",
            role_id="engineering_agent",
            source_commit=COMMIT,
            workspace_digest=workspace_tree_digest(workspace),
            command=("python", "-m", "unittest", "discover", "-s", "tests"),
            environment_digest=policy.environment_digest,
            timeout_seconds=120,
            expected_runner_identity=policy.runner_identity,
        )

    def test_policy_requires_immutable_image_digest(self):
        with self.assertRaises(SandboxContractError):
            DockerSandboxPolicy(image_ref="python:3.12-slim")

    def test_policy_accepts_local_content_addressed_image_id(self):
        self.assertEqual(DockerSandboxPolicy(image_ref=LOCAL_IMAGE).image_ref, LOCAL_IMAGE)

    def test_policy_digest_changes_when_security_environment_changes(self):
        first = DockerSandboxPolicy(image_ref=IMAGE)
        second = replace(first, memory="3g")
        self.assertNotEqual(first.environment_digest, second.environment_digest)

    def test_workspace_digest_changes_with_content(self):
        with tempfile.TemporaryDirectory() as temp:
            workspace = self._workspace(temp)
            first = workspace_tree_digest(workspace)
            (workspace / "app.py").write_text("print('changed')\n", encoding="utf-8")
            self.assertNotEqual(first, workspace_tree_digest(workspace))

    def test_workspace_digest_ignores_runtime_caches(self):
        with tempfile.TemporaryDirectory() as temp:
            workspace = self._workspace(temp)
            first = workspace_tree_digest(workspace)
            cache = workspace / "__pycache__"
            cache.mkdir()
            (cache / "junk.pyc").write_bytes(b"junk")
            self.assertEqual(first, workspace_tree_digest(workspace))

    def test_wrong_workspace_digest_fails_before_docker(self):
        with tempfile.TemporaryDirectory() as temp:
            workspace = self._workspace(temp)
            policy = DockerSandboxPolicy(image_ref=IMAGE)
            req = replace(
                self._request(workspace, policy),
                workspace_digest="sha256:" + "f" * 64,
            )
            runner = FakeRunner()
            adapter = DockerSandboxAdapter(workspace, policy, process_runner=runner)
            with self.assertRaises(SandboxExecutionError):
                asyncio.run(adapter.execute(req))
            self.assertEqual(runner.calls, [])

    def test_wrong_environment_digest_fails_before_docker(self):
        with tempfile.TemporaryDirectory() as temp:
            workspace = self._workspace(temp)
            policy = DockerSandboxPolicy(image_ref=IMAGE)
            req = replace(
                self._request(workspace, policy),
                environment_digest="sha256:" + "f" * 64,
            )
            runner = FakeRunner()
            adapter = DockerSandboxAdapter(workspace, policy, process_runner=runner)
            with self.assertRaises(SandboxExecutionError):
                asyncio.run(adapter.execute(req))
            self.assertEqual(runner.calls, [])

    def test_create_command_enforces_verification_isolation(self):
        with tempfile.TemporaryDirectory() as temp:
            workspace = self._workspace(temp)
            policy = DockerSandboxPolicy(image_ref=IMAGE)
            req = self._request(workspace, policy)
            runner = FakeRunner(
                ProcessResult(0, b"image\n", b""),
                ProcessResult(0, (CONTAINER_ID + "\n").encode(), b""),
                ProcessResult(0, b"tests passed\n", b""),
                ProcessResult(0, b"0\n", b""),
                ProcessResult(0, b"", b""),
            )
            adapter = DockerSandboxAdapter(workspace, policy, process_runner=runner)
            receipt = asyncio.run(adapter.execute(req))

            create_argv = runner.calls[1][0]
            self.assertIn("--pull=never", create_argv)
            self.assertIn("--network=none", create_argv)
            self.assertIn("--read-only", create_argv)
            self.assertIn("--cap-drop=ALL", create_argv)
            self.assertIn("--security-opt=no-new-privileges:true", create_argv)
            self.assertNotIn("--privileged", create_argv)
            self.assertFalse(any("docker.sock" in arg for arg in create_argv))
            for expected_label in (
                "factory.sandbox=true",
                f"factory.runtime_session_id={req.request_id}",
                f"factory.request_id={req.request_id}",
                f"factory.task_id={req.task_id}",
                f"factory.lease_id={req.lease_id}",
                f"factory.role_id={req.role_id}",
                f"factory.source_commit={req.source_commit}",
                f"factory.runner_identity={policy.runner_identity}",
            ):
                self.assertIn(expected_label, create_argv)
            self.assertEqual(create_argv[-len(req.command) :], req.command)
            self.assertEqual(receipt.workspace_digest, req.workspace_digest)
            self.assertEqual(receipt.exit_code, 0)
            self.assertFalse(receipt.timed_out)
            validate_sandbox_receipt(req, receipt, now=receipt.finished_at + timedelta(seconds=1))

    def test_nonzero_container_exit_is_preserved_and_fails_validation(self):
        with tempfile.TemporaryDirectory() as temp:
            workspace = self._workspace(temp)
            policy = DockerSandboxPolicy(image_ref=IMAGE)
            req = self._request(workspace, policy)
            runner = FakeRunner(
                ProcessResult(0, b"image\n", b""),
                ProcessResult(0, (CONTAINER_ID + "\n").encode(), b""),
                ProcessResult(0, b"failed\n", b"boom\n"),
                ProcessResult(0, b"7\n", b""),
                ProcessResult(0, b"", b""),
            )
            receipt = asyncio.run(
                DockerSandboxAdapter(workspace, policy, process_runner=runner).execute(req)
            )
            self.assertEqual(receipt.exit_code, 7)
            with self.assertRaises(SandboxContractError):
                validate_sandbox_receipt(req, receipt, now=receipt.finished_at + timedelta(seconds=1))

    def test_timeout_returns_failed_receipt_and_forces_cleanup(self):
        with tempfile.TemporaryDirectory() as temp:
            workspace = self._workspace(temp)
            policy = DockerSandboxPolicy(image_ref=IMAGE)
            req = self._request(workspace, policy)
            runner = FakeRunner(
                ProcessResult(0, b"image\n", b""),
                ProcessResult(0, (CONTAINER_ID + "\n").encode(), b""),
                ProcessTimeout("timeout"),
                ProcessResult(0, b"", b""),
            )
            receipt = asyncio.run(
                DockerSandboxAdapter(workspace, policy, process_runner=runner).execute(req)
            )
            self.assertTrue(receipt.timed_out)
            self.assertIsNone(receipt.exit_code)
            self.assertEqual(runner.calls[-1][0], ("docker", "rm", "-f", CONTAINER_ID))
            with self.assertRaises(SandboxContractError):
                validate_sandbox_receipt(req, receipt, now=receipt.finished_at + timedelta(seconds=1))

    def test_missing_pinned_image_fails_closed(self):
        with tempfile.TemporaryDirectory() as temp:
            workspace = self._workspace(temp)
            policy = DockerSandboxPolicy(image_ref=IMAGE)
            req = self._request(workspace, policy)
            runner = FakeRunner(ProcessResult(1, b"", b"not found"))
            with self.assertRaises(SandboxExecutionError):
                asyncio.run(
                    DockerSandboxAdapter(workspace, policy, process_runner=runner).execute(req)
                )


if __name__ == "__main__":
    unittest.main()
