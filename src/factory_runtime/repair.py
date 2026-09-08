"""Bounded, non-authoritative CI repair controller.

The repair strategy may edit only a disposable candidate workspace. It never
controls the verification command, task/lease/role/commit bindings, attempt cap,
or success decision. The controller re-runs the exact original failing command
through the Factory runtime after every candidate change and returns either a
verified local candidate or a deterministic escalation.

No GitHub push/PR/release/state authority exists in this module.
"""

from __future__ import annotations

import re
import shutil
import tempfile
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Protocol

from .detector import BaseImagePolicy
from .docker_provisioner import DockerProvisioningPolicy
from .pipeline import (
    DockerVerificationFactory,
    RuntimeInvocation,
    RuntimeObservation,
    RuntimePipeline,
    build_docker_runtime_pipeline,
)
from .sandbox import ValidatedSandboxReceipt, validate_sandbox_receipt
from .docker_sandbox import workspace_tree_digest


REPAIR_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$")
_CANDIDATE_EXCLUDES = {".git", ".pytest_cache", "__pycache__"}


class RepairControllerError(RuntimeError):
    """Raised for invalid repair-controller configuration or requests."""


class RepairEscalationReason(StrEnum):
    INITIAL_COMMAND_PASSED = "INITIAL_COMMAND_PASSED"
    INITIAL_TIMEOUT = "INITIAL_TIMEOUT"
    INITIAL_RUNTIME_FAILURE = "INITIAL_RUNTIME_FAILURE"
    STRATEGY_FAILURE = "STRATEGY_FAILURE"
    AUTHORITATIVE_WORKSPACE_CHANGED = "AUTHORITATIVE_WORKSPACE_CHANGED"
    NO_CANDIDATE_CHANGE = "NO_CANDIDATE_CHANGE"
    CANDIDATE_RUNTIME_FAILURE = "CANDIDATE_RUNTIME_FAILURE"
    VERIFICATION_TIMEOUT = "VERIFICATION_TIMEOUT"
    ATTEMPT_LIMIT_REACHED = "ATTEMPT_LIMIT_REACHED"


@dataclass(frozen=True)
class RepairPolicy:
    """Hard limits controlled outside the repair strategy."""

    max_attempts: int = 3

    def __post_init__(self) -> None:
        if isinstance(self.max_attempts, bool) or not isinstance(self.max_attempts, int):
            raise RepairControllerError("max_attempts must be an integer")
        if self.max_attempts < 1 or self.max_attempts > 8:
            raise RepairControllerError("max_attempts must be between 1 and 8")


@dataclass(frozen=True)
class RepairRequest:
    repair_id: str
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
        if not isinstance(self.repair_id, str) or not REPAIR_ID.fullmatch(self.repair_id):
            raise RepairControllerError("repair_id is invalid or too long")
        # Reuse RuntimeInvocation as the canonical binding validator.
        self.runtime_invocation("validation")

    def runtime_invocation(self, phase: str) -> RuntimeInvocation:
        if not isinstance(phase, str) or not phase or len(phase) > 24 or not REPAIR_ID.fullmatch(phase):
            raise RepairControllerError("repair phase identifier is invalid")
        return RuntimeInvocation(
            run_id=f"{self.repair_id}.{phase}",
            task_id=self.task_id,
            lease_id=self.lease_id,
            role_id=self.role_id,
            source_commit=self.source_commit,
            command=self.command,
            expected_provisioner_identity=self.expected_provisioner_identity,
            expected_runner_identity=self.expected_runner_identity,
            provisioning_timeout_seconds=self.provisioning_timeout_seconds,
            verification_timeout_seconds=self.verification_timeout_seconds,
        )


@dataclass(frozen=True)
class RepairContext:
    """Read-only context supplied to a candidate-editing strategy."""

    repair_id: str
    attempt_number: int
    original_command: tuple[str, ...]
    initial_failure: RuntimeObservation
    previous_failure: RuntimeObservation


@dataclass(frozen=True)
class RepairAction:
    """Strategy bookkeeping only; it carries no authority or success verdict."""

    summary: str

    def __post_init__(self) -> None:
        if not isinstance(self.summary, str) or not self.summary.strip():
            raise RepairControllerError("repair action summary must be nonempty")
        if len(self.summary) > 512:
            raise RepairControllerError("repair action summary exceeds 512 characters")


class RepairStrategy(Protocol):
    async def apply(self, workspace: Path, context: RepairContext) -> RepairAction:
        """Edit the supplied disposable workspace and describe the attempted fix."""
        ...


class RuntimePipelineFactory(Protocol):
    def create(self, workspace: Path) -> RuntimePipeline:
        ...


@dataclass(frozen=True)
class DockerRuntimePipelineFactory:
    image_policy: BaseImagePolicy
    provisioning_policy: DockerProvisioningPolicy
    verification_factory: DockerVerificationFactory | None = None

    def create(self, workspace: Path) -> RuntimePipeline:
        return build_docker_runtime_pipeline(
            workspace,
            self.image_policy,
            self.provisioning_policy,
            verification_factory=self.verification_factory,
        )


@dataclass(frozen=True)
class VerifiedRepairCandidate:
    """A local candidate that passed the exact original command.

    The candidate is intentionally not committed, pushed, merged, or promoted to
    Factory Evidence. The caller owns cleanup of `workspace` after handoff.
    """

    workspace: Path
    workspace_digest: str
    attempt_number: int
    verification: ValidatedSandboxReceipt
    initial_failure: RuntimeObservation
    actions: tuple[RepairAction, ...]

    def cleanup(self) -> None:
        shutil.rmtree(self.workspace, ignore_errors=True)


@dataclass(frozen=True)
class RepairEscalation:
    reason: RepairEscalationReason
    attempts: int
    initial_failure: RuntimeObservation | None
    last_failure: RuntimeObservation | None
    actions: tuple[RepairAction, ...] = ()


RepairOutcome = VerifiedRepairCandidate | RepairEscalation


def _copy_candidate(source: Path) -> Path:
    parent = Path(tempfile.mkdtemp(prefix="factory-repair-"))
    candidate = parent / "workspace"

    def ignore(_directory: str, names: list[str]) -> set[str]:
        return {name for name in names if name in _CANDIDATE_EXCLUDES}

    shutil.copytree(source, candidate, symlinks=True, ignore=ignore)
    return candidate


def _cleanup_candidate(candidate: Path | None) -> None:
    if candidate is None:
        return
    parent = candidate.parent
    if parent.name.startswith("factory-repair-"):
        shutil.rmtree(parent, ignore_errors=True)
    else:
        shutil.rmtree(candidate, ignore_errors=True)


class BoundedCIRepairController:
    """Reproduce -> mutate candidate -> re-run exact command, with hard caps."""

    def __init__(
        self,
        authoritative_workspace: Path,
        pipeline_factory: RuntimePipelineFactory,
        strategy: RepairStrategy,
        policy: RepairPolicy | None = None,
    ) -> None:
        self.authoritative_workspace = authoritative_workspace.resolve()
        if not self.authoritative_workspace.is_dir():
            raise RepairControllerError("authoritative workspace must be an existing directory")
        self.pipeline_factory = pipeline_factory
        self.strategy = strategy
        self.policy = policy or RepairPolicy()

    async def repair(self, request: RepairRequest) -> RepairOutcome:
        authoritative_digest = workspace_tree_digest(self.authoritative_workspace)

        try:
            initial = await self.pipeline_factory.create(self.authoritative_workspace).observe(
                request.runtime_invocation("initial")
            )
        except Exception:
            return RepairEscalation(
                reason=RepairEscalationReason.INITIAL_RUNTIME_FAILURE,
                attempts=0,
                initial_failure=None,
                last_failure=None,
            )

        if workspace_tree_digest(self.authoritative_workspace) != authoritative_digest:
            return RepairEscalation(
                reason=RepairEscalationReason.AUTHORITATIVE_WORKSPACE_CHANGED,
                attempts=0,
                initial_failure=initial,
                last_failure=initial,
            )

        initial_receipt = initial.verification.receipt
        if initial_receipt.timed_out:
            return RepairEscalation(
                reason=RepairEscalationReason.INITIAL_TIMEOUT,
                attempts=0,
                initial_failure=initial,
                last_failure=initial,
            )
        if initial_receipt.exit_code == 0:
            return RepairEscalation(
                reason=RepairEscalationReason.INITIAL_COMMAND_PASSED,
                attempts=0,
                initial_failure=initial,
                last_failure=initial,
            )

        candidate: Path | None = None
        actions: list[RepairAction] = []
        previous_failure = initial
        try:
            candidate = _copy_candidate(self.authoritative_workspace)

            for attempt in range(1, self.policy.max_attempts + 1):
                before_digest = workspace_tree_digest(candidate)
                context = RepairContext(
                    repair_id=request.repair_id,
                    attempt_number=attempt,
                    original_command=request.command,
                    initial_failure=initial,
                    previous_failure=previous_failure,
                )
                try:
                    action = await self.strategy.apply(candidate, context)
                except Exception:
                    return RepairEscalation(
                        reason=RepairEscalationReason.STRATEGY_FAILURE,
                        attempts=attempt,
                        initial_failure=initial,
                        last_failure=previous_failure,
                        actions=tuple(actions),
                    )
                actions.append(action)

                if workspace_tree_digest(self.authoritative_workspace) != authoritative_digest:
                    return RepairEscalation(
                        reason=RepairEscalationReason.AUTHORITATIVE_WORKSPACE_CHANGED,
                        attempts=attempt,
                        initial_failure=initial,
                        last_failure=previous_failure,
                        actions=tuple(actions),
                    )

                after_digest = workspace_tree_digest(candidate)
                if after_digest == before_digest:
                    return RepairEscalation(
                        reason=RepairEscalationReason.NO_CANDIDATE_CHANGE,
                        attempts=attempt,
                        initial_failure=initial,
                        last_failure=previous_failure,
                        actions=tuple(actions),
                    )

                try:
                    observed = await self.pipeline_factory.create(candidate).observe(
                        request.runtime_invocation(f"attempt-{attempt}")
                    )
                except Exception:
                    return RepairEscalation(
                        reason=RepairEscalationReason.CANDIDATE_RUNTIME_FAILURE,
                        attempts=attempt,
                        initial_failure=initial,
                        last_failure=previous_failure,
                        actions=tuple(actions),
                    )

                if workspace_tree_digest(self.authoritative_workspace) != authoritative_digest:
                    return RepairEscalation(
                        reason=RepairEscalationReason.AUTHORITATIVE_WORKSPACE_CHANGED,
                        attempts=attempt,
                        initial_failure=initial,
                        last_failure=observed,
                        actions=tuple(actions),
                    )

                receipt = observed.verification.receipt
                if receipt.timed_out:
                    return RepairEscalation(
                        reason=RepairEscalationReason.VERIFICATION_TIMEOUT,
                        attempts=attempt,
                        initial_failure=initial,
                        last_failure=observed,
                        actions=tuple(actions),
                    )
                if receipt.exit_code == 0:
                    # Hard success gate lives in the controller, outside strategy control.
                    verified = validate_sandbox_receipt(
                        observed.verification_request,
                        receipt,
                    )
                    verified_digest = workspace_tree_digest(candidate)
                    if verified_digest != observed.workspace_digest:
                        return RepairEscalation(
                            reason=RepairEscalationReason.CANDIDATE_RUNTIME_FAILURE,
                            attempts=attempt,
                            initial_failure=initial,
                            last_failure=observed,
                            actions=tuple(actions),
                        )
                    result = VerifiedRepairCandidate(
                        workspace=candidate,
                        workspace_digest=verified_digest,
                        attempt_number=attempt,
                        verification=verified,
                        initial_failure=initial,
                        actions=tuple(actions),
                    )
                    candidate = None  # transfer lifecycle ownership to caller
                    return result

                previous_failure = observed

            return RepairEscalation(
                reason=RepairEscalationReason.ATTEMPT_LIMIT_REACHED,
                attempts=self.policy.max_attempts,
                initial_failure=initial,
                last_failure=previous_failure,
                actions=tuple(actions),
            )
        finally:
            _cleanup_candidate(candidate)
