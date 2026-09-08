from __future__ import annotations

import sys
import unittest
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from factory_runtime.environment import (  # noqa: E402
    EnvironmentSpec,
    ProvisionInput,
    ProvisionStep,
    ProvisioningContractError,
    ProvisioningReceipt,
    ProvisioningRequest,
    validate_provisioning_receipt,
)


NOW = datetime(2026, 9, 8, 5, 30, 0, tzinfo=timezone.utc)
BASE_IMAGE = "python@sha256:" + "a" * 64
RESULT_IMAGE = "factory-python-env@sha256:" + "b" * 64
COMMIT = "c" * 40
WORKSPACE = "sha256:" + "d" * 64
INPUT_DIGEST = "sha256:" + "e" * 64
LOG_DIGEST = "sha256:" + "f" * 64


def spec() -> EnvironmentSpec:
    return EnvironmentSpec(
        stack="python",
        base_image_ref=BASE_IMAGE,
        inputs=(
            ProvisionInput("pyproject.toml", INPUT_DIGEST),
            ProvisionInput("requirements-ci.txt", "sha256:" + "1" * 64),
        ),
        steps=(
            ProvisionStep(
                "install-ci-deps",
                ("python", "-m", "pip", "install", "--require-hashes", "-r", "requirements-ci.txt"),
                network_required=True,
            ),
        ),
        network_policy_id="python-package-registry-v1",
    )


def request(environment: EnvironmentSpec | None = None) -> ProvisioningRequest:
    environment = environment or spec()
    return ProvisioningRequest(
        request_id="provision-1",
        task_id="task-1",
        lease_id="lease-1",
        role_id="engineering_agent",
        source_commit=COMMIT,
        workspace_digest=WORKSPACE,
        environment_spec_digest=environment.digest,
        max_seconds=900,
        expected_provisioner_identity="factory_environment_builder_v1",
    )


def receipt(req: ProvisioningRequest | None = None) -> ProvisioningReceipt:
    req = req or request()
    return ProvisioningReceipt(
        request_id=req.request_id,
        task_id=req.task_id,
        lease_id=req.lease_id,
        role_id=req.role_id,
        source_commit=req.source_commit,
        workspace_digest=req.workspace_digest,
        environment_spec_digest=req.environment_spec_digest,
        provisioner_identity=req.expected_provisioner_identity,
        result_image_ref=RESULT_IMAGE,
        started_at=NOW - timedelta(seconds=30),
        finished_at=NOW - timedelta(seconds=1),
        exit_code=0,
        timed_out=False,
        build_log_digest=LOG_DIGEST,
    )


class EnvironmentProvisioningContractTests(unittest.TestCase):
    def test_base_image_must_be_digest_pinned(self):
        with self.assertRaises(ProvisioningContractError):
            replace(spec(), base_image_ref="python:3.12-slim")

    def test_provision_step_rejects_shell_execution(self):
        with self.assertRaises(ProvisioningContractError):
            ProvisionStep("bad", ("sh", "-c", "pip install -r requirements.txt"))

    def test_networked_step_requires_explicit_network_policy(self):
        with self.assertRaises(ProvisioningContractError):
            replace(spec(), network_policy_id=None)

    def test_duplicate_environment_input_paths_are_denied(self):
        duplicate = ProvisionInput("pyproject.toml", "sha256:" + "2" * 64)
        with self.assertRaises(ProvisioningContractError):
            replace(spec(), inputs=spec().inputs + (duplicate,))

    def test_parent_traversal_input_path_is_denied(self):
        with self.assertRaises(ProvisioningContractError):
            ProvisionInput("../requirements.txt", INPUT_DIGEST)

    def test_environment_digest_is_stable_across_input_order(self):
        original = spec()
        reordered = replace(original, inputs=tuple(reversed(original.inputs)))
        self.assertEqual(original.digest, reordered.digest)

    def test_environment_digest_changes_when_step_changes(self):
        original = spec()
        changed = replace(
            original,
            steps=(
                ProvisionStep(
                    "install-ci-deps",
                    ("python", "-m", "pip", "install", "-r", "requirements-ci.txt"),
                    network_required=True,
                ),
            ),
        )
        self.assertNotEqual(original.digest, changed.digest)

    def test_successful_receipt_validates_but_is_not_factory_evidence(self):
        environment = spec()
        req = request(environment)
        validated = validate_provisioning_receipt(req, environment, receipt(req), now=NOW)
        self.assertEqual(validated.receipt.result_image_ref, RESULT_IMAGE)
        self.assertFalse(hasattr(validated, "signature_valid"))
        self.assertFalse(hasattr(validated, "producer_identity"))

    def test_request_rejects_spec_mismatch(self):
        environment = spec()
        req = replace(request(environment), environment_spec_digest="sha256:" + "3" * 64)
        with self.assertRaises(ProvisioningContractError):
            validate_provisioning_receipt(req, environment, receipt(req), now=NOW)

    def test_wrong_workspace_binding_is_denied(self):
        environment = spec()
        req = request(environment)
        with self.assertRaises(ProvisioningContractError):
            validate_provisioning_receipt(
                req,
                environment,
                replace(receipt(req), workspace_digest="sha256:" + "4" * 64),
                now=NOW,
            )

    def test_wrong_provisioner_identity_is_denied(self):
        environment = spec()
        req = request(environment)
        with self.assertRaises(ProvisioningContractError):
            validate_provisioning_receipt(
                req,
                environment,
                replace(receipt(req), provisioner_identity="unexpected_builder"),
                now=NOW,
            )

    def test_result_image_must_be_digest_pinned(self):
        req = request()
        with self.assertRaises(ProvisioningContractError):
            replace(receipt(req), result_image_ref="factory-python-env:latest")

    def test_nonzero_exit_is_denied(self):
        environment = spec()
        req = request(environment)
        with self.assertRaises(ProvisioningContractError):
            validate_provisioning_receipt(req, environment, replace(receipt(req), exit_code=1), now=NOW)

    def test_timeout_is_denied(self):
        environment = spec()
        req = request(environment)
        with self.assertRaises(ProvisioningContractError):
            validate_provisioning_receipt(
                req,
                environment,
                replace(receipt(req), exit_code=None, timed_out=True),
                now=NOW,
            )

    def test_future_dated_receipt_is_denied(self):
        environment = spec()
        req = request(environment)
        future = replace(
            receipt(req),
            started_at=NOW + timedelta(seconds=1),
            finished_at=NOW + timedelta(seconds=2),
        )
        with self.assertRaises(ProvisioningContractError):
            validate_provisioning_receipt(req, environment, future, now=NOW)

    def test_overlong_provisioning_is_denied(self):
        environment = spec()
        req = replace(request(environment), max_seconds=10)
        long_receipt = replace(
            receipt(req),
            started_at=NOW - timedelta(seconds=20),
            finished_at=NOW - timedelta(seconds=1),
        )
        with self.assertRaises(ProvisioningContractError):
            validate_provisioning_receipt(req, environment, long_receipt, now=NOW)

    def test_request_digest_changes_with_environment_spec(self):
        environment = spec()
        req = request(environment)
        changed = replace(req, environment_spec_digest="sha256:" + "5" * 64)
        self.assertNotEqual(req.digest, changed.digest)


if __name__ == "__main__":
    unittest.main()
