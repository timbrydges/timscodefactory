from __future__ import annotations

import sys
import tempfile
import unittest
from unittest.mock import patch
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from factory_runtime.detector import BaseImagePolicy  # noqa: E402
from factory_runtime.docker_provisioner import (  # noqa: E402
    DockerEnvironmentProvisioner,
    DockerProvisioningPolicy,
)
from factory_runtime.pipeline import (  # noqa: E402
    DockerVerificationFactory,
    build_docker_runtime_pipeline,
)


class ConcreteRuntimePipelineTests(unittest.TestCase):
    def test_default_verification_user_tracks_non_root_host_identity(self):
        with tempfile.TemporaryDirectory() as tmp:
            factory = DockerVerificationFactory()
            with patch("factory_runtime.pipeline.os.geteuid", return_value=1234), patch(
                "factory_runtime.pipeline.os.getegid", return_value=5678
            ):
                binding = factory.create(
                    workspace=Path(tmp),
                    image_ref="python@sha256:" + "a" * 64,
                    expected_runner_identity="factory_docker_sandbox_v1",
                )
            self.assertEqual(binding.adapter.policy.user, "1234:5678")

    def test_default_verification_user_refuses_root_host_process(self):
        with tempfile.TemporaryDirectory() as tmp:
            factory = DockerVerificationFactory()
            with patch("factory_runtime.pipeline.os.geteuid", return_value=0), patch(
                "factory_runtime.pipeline.os.getegid", return_value=0
            ):
                with self.assertRaisesRegex(RuntimeError, "refuses a root host process"):
                    factory.create(
                        workspace=Path(tmp),
                        image_ref="python@sha256:" + "a" * 64,
                        expected_runner_identity="factory_docker_sandbox_v1",
                    )

    def test_builder_wires_same_container_cli_across_provision_and_verify(self):
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            image_policy = BaseImagePolicy(
                images=(("python:3.12", "python@sha256:" + "a" * 64),),
                network_policy_id="package-registry-v1",
            )
            provisioning_policy = DockerProvisioningPolicy(
                network_bindings=(("package-registry-v1", "factory-egress-python"),),
                docker_executable="podman",
            )

            pipeline = build_docker_runtime_pipeline(
                workspace,
                image_policy,
                provisioning_policy,
            )

            self.assertIsInstance(pipeline.provisioner, DockerEnvironmentProvisioner)
            self.assertEqual(pipeline.provisioner.policy.docker_executable, "podman")
            self.assertIsInstance(pipeline.verification_factory, DockerVerificationFactory)
            self.assertEqual(pipeline.verification_factory.docker_executable, "podman")


if __name__ == "__main__":
    unittest.main()
