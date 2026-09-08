from __future__ import annotations

import asyncio
import sys
import tempfile
import unittest
from dataclasses import replace
from datetime import timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from factory_runtime.docker_provisioner import (  # noqa: E402
    DockerEnvironmentProvisioner,
    DockerProvisioningPolicy,
    ProvisioningExecutionError,
)
from factory_runtime.docker_sandbox import ProcessResult, ProcessTimeout, workspace_tree_digest  # noqa: E402
from factory_runtime.environment import (  # noqa: E402
    EnvironmentSpec,
    ProvisionInput,
    ProvisionStep,
    ProvisioningContractError,
    ProvisioningRequest,
    validate_provisioning_receipt,
)


BASE_IMAGE = "python@sha256:" + "a" * 64
IMAGE_ID = "sha256:" + "d" * 64
CONTAINER_ID = "c" * 64
COMMIT = "b" * 40
NETWORK_POLICY = "python-package-registry-v1"
NETWORK = "factory-pypi-egress"


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


class DockerProvisionerTests(unittest.TestCase):
    def _workspace(self, root: str) -> Path:
        workspace = Path(root) / "repo"
        workspace.mkdir()
        (workspace / "pyproject.toml").write_text(
            '[project]\nname="x"\nrequires-python=">=3.12"\ndependencies=[]\n',
            encoding="utf-8",
        )
        (workspace / "requirements-ci.txt").write_text(
            "jsonschema==4.26.0 --hash=sha256:" + "e" * 64 + "\n",
            encoding="utf-8",
        )
        return workspace

    def _spec(self, workspace: Path) -> EnvironmentSpec:
        return EnvironmentSpec(
            stack="python",
            base_image_ref=BASE_IMAGE,
            inputs=(
                ProvisionInput(
                    "pyproject.toml",
                    "sha256:" + __import__("hashlib").sha256(
                        (workspace / "pyproject.toml").read_bytes()
                    ).hexdigest(),
                ),
                ProvisionInput(
                    "requirements-ci.txt",
                    "sha256:" + __import__("hashlib").sha256(
                        (workspace / "requirements-ci.txt").read_bytes()
                    ).hexdigest(),
                ),
            ),
            steps=(
                ProvisionStep(
                    "install-python-dependencies",
                    (
                        "python",
                        "-m",
                        "pip",
                        "install",
                        "--require-hashes",
                        "-r",
                        "requirements-ci.txt",
                    ),
                    timeout_seconds=900,
                    network_required=True,
                ),
            ),
            network_policy_id=NETWORK_POLICY,
        )

    def _request(
        self,
        workspace: Path,
        spec: EnvironmentSpec,
        policy: DockerProvisioningPolicy,
    ) -> ProvisioningRequest:
        return ProvisioningRequest(
            request_id="provision-docker-1",
            task_id="task-1",
            lease_id="lease-1",
            role_id="engineering_agent",
            source_commit=COMMIT,
            workspace_digest=workspace_tree_digest(workspace),
            environment_spec_digest=spec.digest,
            max_seconds=1200,
            expected_provisioner_identity=policy.provisioner_identity,
        )

    def _policy(self) -> DockerProvisioningPolicy:
        return DockerProvisioningPolicy(
            network_bindings=((NETWORK_POLICY, NETWORK),),
        )

    def _success_responses(self):
        return (
            ProcessResult(0, b"base\n"),
            ProcessResult(0, f"true|{NETWORK_POLICY}\n".encode()),
            ProcessResult(0, (CONTAINER_ID + "\n").encode()),
            ProcessResult(0),
            ProcessResult(0),
            ProcessResult(0),
            ProcessResult(0),
            ProcessResult(0, b"installed\n"),
            ProcessResult(0),
            ProcessResult(0),
            ProcessResult(0, (IMAGE_ID + "\n").encode()),
            ProcessResult(0, (IMAGE_ID + "\n").encode()),
            ProcessResult(0),
        )

    def test_policy_rejects_default_unrestricted_networks(self):
        for name in ("bridge", "host", "default", "none"):
            with self.subTest(name=name), self.assertRaises(ProvisioningExecutionError):
                DockerProvisioningPolicy(network_bindings=((NETWORK_POLICY, name),))

    def test_successful_python_build_uses_controlled_egress_and_returns_image_id(self):
        with tempfile.TemporaryDirectory() as temp:
            workspace = self._workspace(temp)
            spec = self._spec(workspace)
            policy = self._policy()
            request = self._request(workspace, spec, policy)
            runner = FakeRunner(*self._success_responses())
            receipt = asyncio.run(
                DockerEnvironmentProvisioner(
                    workspace,
                    policy,
                    process_runner=runner,
                ).provision(request, spec)
            )

            create = runner.calls[2][0]
            self.assertIn("--pull=never", create)
            self.assertIn("--network=none", create)
            self.assertIn("--cap-drop=ALL", create)
            self.assertIn("--security-opt=no-new-privileges:true", create)
            self.assertNotIn("--privileged", create)
            self.assertFalse(any("docker.sock" in arg for arg in create))

            connect = runner.calls[6][0]
            step = runner.calls[7][0]
            disconnect = runner.calls[8][0]
            self.assertEqual(connect, ("docker", "network", "connect", NETWORK, CONTAINER_ID))
            self.assertEqual(disconnect, ("docker", "network", "disconnect", NETWORK, CONTAINER_ID))
            self.assertEqual(step[-len(spec.steps[0].argv) :], spec.steps[0].argv)
            self.assertNotIn("sh", step)
            self.assertNotIn("bash", step)

            self.assertEqual(receipt.result_image_ref, IMAGE_ID)
            self.assertEqual(receipt.exit_code, 0)
            self.assertFalse(receipt.timed_out)
            validate_provisioning_receipt(
                request,
                spec,
                receipt,
                now=receipt.finished_at + timedelta(seconds=1),
            )

    def test_node_spec_fails_before_docker(self):
        with tempfile.TemporaryDirectory() as temp:
            workspace = self._workspace(temp)
            python_spec = self._spec(workspace)
            node_spec = replace(python_spec, stack="node")
            policy = self._policy()
            request = self._request(workspace, node_spec, policy)
            runner = FakeRunner()
            with self.assertRaises(ProvisioningExecutionError):
                asyncio.run(
                    DockerEnvironmentProvisioner(workspace, policy, process_runner=runner).provision(
                        request, node_spec
                    )
                )
            self.assertEqual(runner.calls, [])

    def test_arbitrary_provision_step_fails_before_docker(self):
        with tempfile.TemporaryDirectory() as temp:
            workspace = self._workspace(temp)
            spec = replace(
                self._spec(workspace),
                steps=(ProvisionStep("bad", ("python", "setup.py", "install"), network_required=True),),
            )
            policy = self._policy()
            request = self._request(workspace, spec, policy)
            runner = FakeRunner()
            with self.assertRaises(ProvisioningExecutionError):
                asyncio.run(
                    DockerEnvironmentProvisioner(workspace, policy, process_runner=runner).provision(
                        request, spec
                    )
                )
            self.assertEqual(runner.calls, [])

    def test_wrong_workspace_digest_fails_before_docker(self):
        with tempfile.TemporaryDirectory() as temp:
            workspace = self._workspace(temp)
            spec = self._spec(workspace)
            policy = self._policy()
            request = replace(
                self._request(workspace, spec, policy),
                workspace_digest="sha256:" + "f" * 64,
            )
            runner = FakeRunner()
            with self.assertRaises(ProvisioningExecutionError):
                asyncio.run(
                    DockerEnvironmentProvisioner(workspace, policy, process_runner=runner).provision(
                        request, spec
                    )
                )
            self.assertEqual(runner.calls, [])

    def test_missing_network_binding_fails_closed(self):
        with tempfile.TemporaryDirectory() as temp:
            workspace = self._workspace(temp)
            spec = self._spec(workspace)
            policy = DockerProvisioningPolicy()
            request = self._request(workspace, spec, policy)
            runner = FakeRunner(ProcessResult(0, b"base\n"))
            with self.assertRaises(ProvisioningExecutionError):
                asyncio.run(
                    DockerEnvironmentProvisioner(workspace, policy, process_runner=runner).provision(
                        request, spec
                    )
                )

    def test_network_attestation_mismatch_is_denied(self):
        with tempfile.TemporaryDirectory() as temp:
            workspace = self._workspace(temp)
            spec = self._spec(workspace)
            policy = self._policy()
            request = self._request(workspace, spec, policy)
            runner = FakeRunner(
                ProcessResult(0, b"base\n"),
                ProcessResult(0, b"false|wrong-policy\n"),
            )
            with self.assertRaises(ProvisioningExecutionError):
                asyncio.run(
                    DockerEnvironmentProvisioner(workspace, policy, process_runner=runner).provision(
                        request, spec
                    )
                )

    def test_nonzero_step_returns_image_less_failed_receipt(self):
        with tempfile.TemporaryDirectory() as temp:
            workspace = self._workspace(temp)
            spec = self._spec(workspace)
            policy = self._policy()
            request = self._request(workspace, spec, policy)
            runner = FakeRunner(
                ProcessResult(0, b"base\n"),
                ProcessResult(0, f"true|{NETWORK_POLICY}\n".encode()),
                ProcessResult(0, (CONTAINER_ID + "\n").encode()),
                ProcessResult(0),
                ProcessResult(0),
                ProcessResult(0),
                ProcessResult(0),
                ProcessResult(7, b"", b"install failed"),
                ProcessResult(0),
                ProcessResult(0),
            )
            receipt = asyncio.run(
                DockerEnvironmentProvisioner(workspace, policy, process_runner=runner).provision(
                    request, spec
                )
            )
            self.assertEqual(receipt.exit_code, 7)
            self.assertIsNone(receipt.result_image_ref)
            self.assertFalse(receipt.timed_out)
            self.assertFalse(any(call[0][1] == "commit" for call in runner.calls))
            with self.assertRaises(ProvisioningContractError):
                validate_provisioning_receipt(
                    request,
                    spec,
                    receipt,
                    now=receipt.finished_at + timedelta(seconds=1),
                )

    def test_step_timeout_returns_image_less_receipt_and_disconnects(self):
        with tempfile.TemporaryDirectory() as temp:
            workspace = self._workspace(temp)
            spec = self._spec(workspace)
            policy = self._policy()
            request = self._request(workspace, spec, policy)
            runner = FakeRunner(
                ProcessResult(0, b"base\n"),
                ProcessResult(0, f"true|{NETWORK_POLICY}\n".encode()),
                ProcessResult(0, (CONTAINER_ID + "\n").encode()),
                ProcessResult(0),
                ProcessResult(0),
                ProcessResult(0),
                ProcessResult(0),
                ProcessTimeout("timeout"),
                ProcessResult(0),
                ProcessResult(0),
            )
            receipt = asyncio.run(
                DockerEnvironmentProvisioner(workspace, policy, process_runner=runner).provision(
                    request, spec
                )
            )
            self.assertTrue(receipt.timed_out)
            self.assertIsNone(receipt.exit_code)
            self.assertIsNone(receipt.result_image_ref)
            self.assertEqual(
                runner.calls[8][0],
                ("docker", "network", "disconnect", NETWORK, CONTAINER_ID),
            )
            with self.assertRaises(ProvisioningContractError):
                validate_provisioning_receipt(
                    request,
                    spec,
                    receipt,
                    now=receipt.finished_at + timedelta(seconds=1),
                )

    def test_invalid_committed_image_id_fails_closed(self):
        with tempfile.TemporaryDirectory() as temp:
            workspace = self._workspace(temp)
            spec = self._spec(workspace)
            policy = self._policy()
            request = self._request(workspace, spec, policy)
            responses = list(self._success_responses())
            responses[10] = ProcessResult(0, b"not-an-image-id\n")
            # Commit failure skips the image-inspect response, so leave cleanup
            # immediately after the bad commit result.
            responses.pop(11)
            runner = FakeRunner(*responses)
            with self.assertRaises(ProvisioningExecutionError):
                asyncio.run(
                    DockerEnvironmentProvisioner(workspace, policy, process_runner=runner).provision(
                        request, spec
                    )
                )
            self.assertEqual(runner.calls[-1][0], ("docker", "rm", "-f", CONTAINER_ID))

    def test_no_dependency_steps_return_existing_base_without_container(self):
        with tempfile.TemporaryDirectory() as temp:
            workspace = self._workspace(temp)
            spec = EnvironmentSpec(
                stack="python",
                base_image_ref=BASE_IMAGE,
                inputs=(),
                steps=(),
            )
            policy = self._policy()
            request = self._request(workspace, spec, policy)
            runner = FakeRunner(ProcessResult(0, b"base\n"))
            receipt = asyncio.run(
                DockerEnvironmentProvisioner(workspace, policy, process_runner=runner).provision(
                    request, spec
                )
            )
            self.assertEqual(receipt.result_image_ref, BASE_IMAGE)
            self.assertEqual(len(runner.calls), 1)


if __name__ == "__main__":
    unittest.main()
