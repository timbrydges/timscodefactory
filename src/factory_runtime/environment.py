"""Fail-closed environment provisioning contract.

Provisioning is intentionally separated from verification. Provisioners may use
bounded network access to install dependencies and produce an immutable image,
but they remain below the Factory trust boundary and cannot mutate Factory
state. The verification sandbox consumes only digest-pinned images.
"""

from __future__ import annotations

import hashlib
import json
import posixpath
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Protocol

from .sandbox import SandboxContractError


SAFE_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
COMMIT_SHA = re.compile(r"^[0-9a-f]{40}$")
SHA256_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
PINNED_IMAGE = re.compile(r"^[^\s@]+@sha256:[0-9a-f]{64}$")
ALLOWED_STACKS = frozenset({"python", "node", "java", "csharp", "go", "rust", "unknown"})
SHELL_EXECUTABLES = frozenset({"sh", "bash", "dash", "zsh", "fish", "cmd", "cmd.exe", "powershell", "pwsh"})


class ProvisioningContractError(SandboxContractError):
    """Raised when an environment/provisioning object violates the contract."""


def _require_identifier(name: str, value: str) -> None:
    if not isinstance(value, str) or not SAFE_IDENTIFIER.fullmatch(value):
        raise ProvisioningContractError(f"{name} is invalid")


def _require_digest(name: str, value: str) -> None:
    if not isinstance(value, str) or not SHA256_DIGEST.fullmatch(value):
        raise ProvisioningContractError(f"{name} must be a sha256 digest")


def _require_pinned_image(name: str, value: str) -> None:
    if not isinstance(value, str) or not PINNED_IMAGE.fullmatch(value):
        raise ProvisioningContractError(f"{name} must be pinned by sha256 digest")


def _require_aware(name: str, value: datetime) -> None:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise ProvisioningContractError(f"{name} must be timezone-aware")


def _canonical_json(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


@dataclass(frozen=True)
class ProvisionInput:
    """Repo-relative file whose exact content informed environment detection."""

    path: str
    digest: str

    def __post_init__(self) -> None:
        if not isinstance(self.path, str) or not self.path or "\\" in self.path:
            raise ProvisioningContractError("provision input path is invalid")
        normalized = posixpath.normpath(self.path)
        if normalized != self.path or self.path.startswith("/") or normalized in {".", ".."} or normalized.startswith("../"):
            raise ProvisioningContractError("provision input path must be normalized and repo-relative")
        _require_digest("provision input digest", self.digest)

    def to_dict(self) -> dict[str, str]:
        return {"path": self.path, "digest": self.digest}


@dataclass(frozen=True)
class ProvisionStep:
    """One shell-free dependency provisioning action."""

    step_id: str
    argv: tuple[str, ...]
    timeout_seconds: int = 600
    network_required: bool = False

    def __post_init__(self) -> None:
        _require_identifier("step_id", self.step_id)
        if not self.argv or any(not isinstance(item, str) or not item for item in self.argv):
            raise ProvisioningContractError("provision step argv must contain nonempty strings")
        executable = self.argv[0].rsplit("/", 1)[-1].lower()
        if executable in SHELL_EXECUTABLES:
            raise ProvisioningContractError("provision steps may not invoke a command shell")
        if isinstance(self.timeout_seconds, bool) or not isinstance(self.timeout_seconds, int):
            raise ProvisioningContractError("step timeout_seconds must be an integer")
        if self.timeout_seconds < 1 or self.timeout_seconds > 1800:
            raise ProvisioningContractError("step timeout_seconds must be between 1 and 1800")
        if not isinstance(self.network_required, bool):
            raise ProvisioningContractError("network_required must be boolean")

    def to_dict(self) -> dict[str, object]:
        return {
            "step_id": self.step_id,
            "argv": list(self.argv),
            "timeout_seconds": self.timeout_seconds,
            "network_required": self.network_required,
        }


@dataclass(frozen=True)
class EnvironmentSpec:
    """Deterministic recipe for constructing a verification environment."""

    stack: str
    base_image_ref: str
    inputs: tuple[ProvisionInput, ...]
    steps: tuple[ProvisionStep, ...]
    network_policy_id: str | None = None

    def __post_init__(self) -> None:
        if self.stack not in ALLOWED_STACKS:
            raise ProvisioningContractError("environment stack is unsupported")
        _require_pinned_image("base_image_ref", self.base_image_ref)
        input_paths = [item.path for item in self.inputs]
        if len(set(input_paths)) != len(input_paths):
            raise ProvisioningContractError("environment inputs contain duplicate paths")
        step_ids = [item.step_id for item in self.steps]
        if len(set(step_ids)) != len(step_ids):
            raise ProvisioningContractError("environment steps contain duplicate ids")
        requires_network = any(step.network_required for step in self.steps)
        if requires_network:
            if self.network_policy_id is None:
                raise ProvisioningContractError("networked provisioning requires an explicit network policy id")
            _require_identifier("network_policy_id", self.network_policy_id)
        elif self.network_policy_id is not None:
            _require_identifier("network_policy_id", self.network_policy_id)

    def to_dict(self) -> dict[str, object]:
        return {
            "stack": self.stack,
            "base_image_ref": self.base_image_ref,
            "inputs": [item.to_dict() for item in sorted(self.inputs, key=lambda item: item.path)],
            "steps": [item.to_dict() for item in self.steps],
            "network_policy_id": self.network_policy_id,
        }

    @property
    def digest(self) -> str:
        return "sha256:" + hashlib.sha256(_canonical_json(self.to_dict())).hexdigest()


@dataclass(frozen=True)
class ProvisioningRequest:
    """Controller-bound request passed to a non-authoritative provisioner."""

    request_id: str
    task_id: str
    lease_id: str
    role_id: str
    source_commit: str
    workspace_digest: str
    environment_spec_digest: str
    max_seconds: int
    expected_provisioner_identity: str

    def __post_init__(self) -> None:
        for name in ("request_id", "task_id", "lease_id", "role_id", "expected_provisioner_identity"):
            _require_identifier(name, getattr(self, name))
        if not isinstance(self.source_commit, str) or not COMMIT_SHA.fullmatch(self.source_commit):
            raise ProvisioningContractError("source_commit must be an exact 40-character commit SHA")
        _require_digest("workspace_digest", self.workspace_digest)
        _require_digest("environment_spec_digest", self.environment_spec_digest)
        if isinstance(self.max_seconds, bool) or not isinstance(self.max_seconds, int):
            raise ProvisioningContractError("max_seconds must be an integer")
        if self.max_seconds < 1 or self.max_seconds > 3600:
            raise ProvisioningContractError("max_seconds must be between 1 and 3600")

    @property
    def digest(self) -> str:
        fields = (
            self.request_id,
            self.task_id,
            self.lease_id,
            self.role_id,
            self.source_commit,
            self.workspace_digest,
            self.environment_spec_digest,
            str(self.max_seconds),
            self.expected_provisioner_identity,
        )
        payload = b"\0".join(item.encode("utf-8") for item in fields)
        return "sha256:" + hashlib.sha256(payload).hexdigest()


@dataclass(frozen=True)
class ProvisioningReceipt:
    """Untrusted receipt returned by a dependency provisioner."""

    request_id: str
    task_id: str
    lease_id: str
    role_id: str
    source_commit: str
    workspace_digest: str
    environment_spec_digest: str
    provisioner_identity: str
    result_image_ref: str
    started_at: datetime
    finished_at: datetime
    exit_code: int | None
    timed_out: bool
    build_log_digest: str

    def __post_init__(self) -> None:
        for name in ("request_id", "task_id", "lease_id", "role_id", "provisioner_identity"):
            _require_identifier(name, getattr(self, name))
        if not isinstance(self.source_commit, str) or not COMMIT_SHA.fullmatch(self.source_commit):
            raise ProvisioningContractError("receipt source_commit is invalid")
        _require_digest("workspace_digest", self.workspace_digest)
        _require_digest("environment_spec_digest", self.environment_spec_digest)
        _require_pinned_image("result_image_ref", self.result_image_ref)
        _require_aware("started_at", self.started_at)
        _require_aware("finished_at", self.finished_at)
        if self.exit_code is not None and (isinstance(self.exit_code, bool) or not isinstance(self.exit_code, int)):
            raise ProvisioningContractError("exit_code must be an integer or null")
        if not isinstance(self.timed_out, bool):
            raise ProvisioningContractError("timed_out must be boolean")
        _require_digest("build_log_digest", self.build_log_digest)


@dataclass(frozen=True)
class ValidatedProvisioningReceipt:
    """Deterministically checked provisioning result; still not Factory Evidence."""

    receipt: ProvisioningReceipt
    request_digest: str
    verified_at: datetime


class ProvisionerAdapter(Protocol):
    async def provision(
        self,
        request: ProvisioningRequest,
        spec: EnvironmentSpec,
    ) -> ProvisioningReceipt:
        """Build an immutable verification image and return an untrusted receipt."""
        ...


def validate_provisioning_receipt(
    request: ProvisioningRequest,
    spec: EnvironmentSpec,
    receipt: ProvisioningReceipt,
    *,
    now: datetime | None = None,
) -> ValidatedProvisioningReceipt:
    """Fail closed unless the provisioning result is exactly bound and successful."""

    now = now or datetime.now(timezone.utc)
    _require_aware("now", now)
    if spec.digest != request.environment_spec_digest:
        raise ProvisioningContractError("environment spec does not match authorized request")

    exact_bindings = {
        "request_id": (receipt.request_id, request.request_id),
        "task_id": (receipt.task_id, request.task_id),
        "lease_id": (receipt.lease_id, request.lease_id),
        "role_id": (receipt.role_id, request.role_id),
        "source_commit": (receipt.source_commit, request.source_commit),
        "workspace_digest": (receipt.workspace_digest, request.workspace_digest),
        "environment_spec_digest": (receipt.environment_spec_digest, request.environment_spec_digest),
        "provisioner_identity": (receipt.provisioner_identity, request.expected_provisioner_identity),
    }
    for field, (actual, expected) in exact_bindings.items():
        if actual != expected:
            raise ProvisioningContractError(f"receipt {field} does not match request")

    if receipt.finished_at < receipt.started_at:
        raise ProvisioningContractError("receipt finished_at precedes started_at")
    if receipt.started_at > now or receipt.finished_at > now:
        raise ProvisioningContractError("future-dated provisioning receipt is invalid")
    if (receipt.finished_at - receipt.started_at).total_seconds() > request.max_seconds:
        raise ProvisioningContractError("provisioning exceeded authorized duration")
    if receipt.timed_out:
        raise ProvisioningContractError("timed-out provisioning cannot produce a trusted environment")
    if receipt.exit_code != 0:
        raise ProvisioningContractError("provisioning must exit zero")

    return ValidatedProvisioningReceipt(
        receipt=receipt,
        request_digest=request.digest,
        verified_at=now,
    )
