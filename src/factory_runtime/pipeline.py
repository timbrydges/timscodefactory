"""Non-authoritative end-to-end Factory runtime composition.

This module composes deterministic environment detection, bounded dependency
provisioning, and hardened verification. It deliberately stops at validated
runtime receipts. It cannot mutate Factory state and cannot manufacture Factory
Evidence; the authoritative Controller must separately attest and consume any
result.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from .detector import BaseImagePolicy, DetectionResult, detect_environment
from .docker_sandbox import DockerSandboxAdapter, DockerSandboxPolicy, workspace_tree_digest
from .environment import (
    ProvisionerAdapter,
    ProvisioningRequest,
    ValidatedProvisioningReceipt,
    validate_provisioning_receipt,
)
from .sandbox import (
    SandboxAdapter,
    SandboxRequest,
    ValidatedSandboxReceipt,
    command_digest,
    validate_sandbox_receipt,
)


RUN_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,95}$")
SAFE_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
COMMIT_SHA = re.compile(r"^[0-9a-f]{40}$")


class RuntimePipelineError(RuntimeError):
    """Raised when composition cannot preserve the Factory runtime contract."""


@dataclass(frozen=True)
class RuntimeInvocation:
    """Controller-bound invocation passed to the non-authoritative runtime."""

    run_id: str
    task_id: str
    lease_id: str
    role_id: str
    source_commit: str
    command: tuple[str, ...]
    expected_provisioner_identity: str
    expected_runner_identity: str
    provisioning_timeout_seconds: int = 1200
    verification_timeout_seconds: int = 600

    def __post_init__(self) -> None:
        if not RUN_ID.fullmatch(self.run_id):
            raise RuntimePipelineError("run_id is invalid or too long")
        for name in (
            "task_id",
            "lease_id",
            "role_id",
            "expected_provisioner_identity",
            "expected_runner_identity",
        ):
            value = getattr(self, name)
            if not isinstance(value, str) or not SAFE_IDENTIFIER.fullmatch(value):
                raise RuntimePipelineError(f"{name} is invalid")
        if not COMMIT_SHA.fullmatch(self.source_commit):
            raise RuntimePipelineError("source_commit must be an exact 40-character commit SHA")
        command_digest(self.command)
        for name, value, upper in (
            ("provisioning_timeout_seconds", self.provisioning_timeout_seconds, 3600),
            ("verification_timeout_seconds", self.verification_timeout_seconds, 3600),
        ):
            if isinstance(value, bool) or not isinstance(value, int) or value < 1 or value > upper:
                raise RuntimePipelineError(f"{name} must be between 1 and {upper}")

    @property
    def provisioning_request_id(self) -> str:
        return f"{self.run_id}.provision"

    @property
    def verification_request_id(self) -> str:
        return f"{self.run_id}.verify"


@dataclass(frozen=True)
class VerificationBinding:
    """Concrete verification adapter plus its exact request bindings."""

    adapter: SandboxAdapter
    environment_digest: str
    runner_identity: str


class VerificationFactory(Protocol):
    def create(
        self,
        *,
        workspace: Path,
        image_ref: str,
        expected_runner_identity: str,
    ) -> VerificationBinding:
        ...


@dataclass(frozen=True)
class DockerVerificationFactory:
    """Create hardened Docker verification adapters after provisioning."""

    docker_executable: str = "docker"
    memory: str = "2g"
    cpus: str = "2"
    pids_limit: int = 256
    user: str = "65532:65532"
    tmpfs_size: str = "256m"

    def create(
        self,
        *,
        workspace: Path,
        image_ref: str,
        expected_runner_identity: str,
    ) -> VerificationBinding:
        policy = DockerSandboxPolicy(
            image_ref=image_ref,
            runner_identity=expected_runner_identity,
            docker_executable=self.docker_executable,
            memory=self.memory,
            cpus=self.cpus,
            pids_limit=self.pids_limit,
            user=self.user,
            tmpfs_size=self.tmpfs_size,
        )
        return VerificationBinding(
            adapter=DockerSandboxAdapter(workspace, policy),
            environment_digest=policy.environment_digest,
            runner_identity=policy.runner_identity,
        )


@dataclass(frozen=True)
class RuntimeResult:
    """Validated runtime receipts; intentionally not authoritative Factory Evidence."""

    detection: DetectionResult
    provisioning: ValidatedProvisioningReceipt
    verification: ValidatedSandboxReceipt
    workspace_digest: str


class RuntimePipeline:
    """Compose detect -> provision -> verify without acquiring state authority."""

    def __init__(
        self,
        workspace: Path,
        image_policy: BaseImagePolicy,
        provisioner: ProvisionerAdapter,
        verification_factory: VerificationFactory,
    ) -> None:
        self.workspace = workspace
        self.image_policy = image_policy
        self.provisioner = provisioner
        self.verification_factory = verification_factory

    def _assert_workspace_unchanged(self, expected_digest: str, boundary: str) -> None:
        actual = workspace_tree_digest(self.workspace)
        if actual != expected_digest:
            raise RuntimePipelineError(f"workspace changed during {boundary}")

    async def run(self, invocation: RuntimeInvocation) -> RuntimeResult:
        workspace_digest = workspace_tree_digest(self.workspace)

        detection = detect_environment(self.workspace, self.image_policy)
        self._assert_workspace_unchanged(workspace_digest, "environment detection")

        provisioning_request = ProvisioningRequest(
            request_id=invocation.provisioning_request_id,
            task_id=invocation.task_id,
            lease_id=invocation.lease_id,
            role_id=invocation.role_id,
            source_commit=invocation.source_commit,
            workspace_digest=workspace_digest,
            environment_spec_digest=detection.spec.digest,
            max_seconds=invocation.provisioning_timeout_seconds,
            expected_provisioner_identity=invocation.expected_provisioner_identity,
        )
        provisioning_receipt = await self.provisioner.provision(
            provisioning_request,
            detection.spec,
        )
        validated_provisioning = validate_provisioning_receipt(
            provisioning_request,
            detection.spec,
            provisioning_receipt,
        )
        image_ref = validated_provisioning.receipt.result_image_ref
        if image_ref is None:
            raise RuntimePipelineError("successful provisioning did not produce an immutable image")

        self._assert_workspace_unchanged(workspace_digest, "environment provisioning")

        verification_binding = self.verification_factory.create(
            workspace=self.workspace,
            image_ref=image_ref,
            expected_runner_identity=invocation.expected_runner_identity,
        )
        if verification_binding.runner_identity != invocation.expected_runner_identity:
            raise RuntimePipelineError("verification factory returned the wrong runner identity")

        verification_request = SandboxRequest(
            request_id=invocation.verification_request_id,
            task_id=invocation.task_id,
            lease_id=invocation.lease_id,
            role_id=invocation.role_id,
            source_commit=invocation.source_commit,
            workspace_digest=workspace_digest,
            command=invocation.command,
            environment_digest=verification_binding.environment_digest,
            timeout_seconds=invocation.verification_timeout_seconds,
            expected_runner_identity=invocation.expected_runner_identity,
        )
        verification_receipt = await verification_binding.adapter.execute(verification_request)
        validated_verification = validate_sandbox_receipt(
            verification_request,
            verification_receipt,
        )

        self._assert_workspace_unchanged(workspace_digest, "verification")

        return RuntimeResult(
            detection=detection,
            provisioning=validated_provisioning,
            verification=validated_verification,
            workspace_digest=workspace_digest,
        )
