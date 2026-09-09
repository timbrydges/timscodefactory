"""Non-authoritative end-to-end Factory runtime composition.

This module composes deterministic environment detection, bounded dependency
provisioning, and hardened verification. It deliberately stops at validated
runtime receipts. It cannot mutate Factory state and cannot manufacture Factory
Evidence; the authoritative Controller must separately attest and consume any
result.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from .detector import BaseImagePolicy, DetectionResult, detect_environment
from .diagnostics import DiagnosticSource, RedactedDiagnosticCapture, RuntimeDiagnostics
from .docker_provisioner import DockerEnvironmentProvisioner, DockerProvisioningPolicy
from .docker_sandbox import DockerSandboxAdapter, DockerSandboxPolicy, workspace_tree_digest
from .environment import (
    ProvisionerAdapter,
    ProvisioningRequest,
    ValidatedProvisioningReceipt,
    validate_provisioning_receipt,
)
from .sandbox import (
    BoundSandboxReceipt,
    SandboxAdapter,
    SandboxRequest,
    ValidatedSandboxReceipt,
    bind_sandbox_receipt,
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
        if not isinstance(self.run_id, str) or not RUN_ID.fullmatch(self.run_id):
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
        if not isinstance(self.source_commit, str) or not COMMIT_SHA.fullmatch(self.source_commit):
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
    diagnostic_source: DiagnosticSource | None = None


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
    user: str | None = None
    tmpfs_size: str = "256m"

    def _resolved_user(self) -> str:
        if self.user is not None:
            return self.user
        uid = os.geteuid()
        gid = os.getegid()
        if uid == 0:
            raise RuntimePipelineError(
                "automatic Docker verification user resolution refuses a root host process"
            )
        return f"{uid}:{gid}"

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
            user=self._resolved_user(),
            tmpfs_size=self.tmpfs_size,
        )
        diagnostic_capture = RedactedDiagnosticCapture()
        return VerificationBinding(
            adapter=DockerSandboxAdapter(
                workspace,
                policy,
                diagnostic_capture=diagnostic_capture,
            ),
            environment_digest=policy.environment_digest,
            runner_identity=policy.runner_identity,
            diagnostic_source=diagnostic_capture,
        )


@dataclass(frozen=True)
class RuntimeObservation:
    """Bound runtime execution outcome that may represent failure.

    The provisioning stage must still succeed, because there is no trustworthy
    verification environment otherwise. The verification outcome may be nonzero
    or timed out, but its exact request binding is trusted. Diagnostics, when
    present, are separately redacted and non-authoritative.
    """

    detection: DetectionResult
    provisioning: ValidatedProvisioningReceipt
    verification_request: SandboxRequest
    verification: BoundSandboxReceipt
    workspace_digest: str
    diagnostics: RuntimeDiagnostics | None = None


@dataclass(frozen=True)
class RuntimeResult:
    """Validated successful runtime receipts; not authoritative Factory Evidence."""

    detection: DetectionResult
    provisioning: ValidatedProvisioningReceipt
    verification: ValidatedSandboxReceipt
    workspace_digest: str


class RuntimePipeline:
    """Compose detect -> provision -> observe/verify without state authority."""

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

    async def observe(self, invocation: RuntimeInvocation) -> RuntimeObservation:
        """Execute the exact command and return a bound success/failure observation."""

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
        bound_verification = bind_sandbox_receipt(
            verification_request,
            verification_receipt,
        )

        diagnostics = None
        if verification_binding.diagnostic_source is not None:
            diagnostics = verification_binding.diagnostic_source.take(
                verification_request,
                verification_receipt,
            )

        self._assert_workspace_unchanged(workspace_digest, "verification")

        return RuntimeObservation(
            detection=detection,
            provisioning=validated_provisioning,
            verification_request=verification_request,
            verification=bound_verification,
            workspace_digest=workspace_digest,
            diagnostics=diagnostics,
        )

    async def run(self, invocation: RuntimeInvocation) -> RuntimeResult:
        """Execute and require a successful exit-zero verification."""

        observed = await self.observe(invocation)
        validated_verification = validate_sandbox_receipt(
            observed.verification_request,
            observed.verification.receipt,
        )
        return RuntimeResult(
            detection=observed.detection,
            provisioning=observed.provisioning,
            verification=validated_verification,
            workspace_digest=observed.workspace_digest,
        )


def build_docker_runtime_pipeline(
    workspace: Path,
    image_policy: BaseImagePolicy,
    provisioning_policy: DockerProvisioningPolicy,
    *,
    verification_factory: DockerVerificationFactory | None = None,
) -> RuntimePipeline:
    """Build the concrete Docker-backed non-authoritative runtime chain."""

    verifier = verification_factory or DockerVerificationFactory(
        docker_executable=provisioning_policy.docker_executable,
    )
    provisioner = DockerEnvironmentProvisioner(
        workspace,
        provisioning_policy,
    )
    return RuntimePipeline(
        workspace,
        image_policy,
        provisioner,
        verifier,
    )
