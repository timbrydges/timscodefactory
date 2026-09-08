"""Fail-closed sandbox adapter contract.

The runtime is below the Factory trust boundary. A sandbox implementation may
execute commands and return a receipt, but that receipt is *not* authoritative
Factory evidence and cannot mutate Factory state. The Controller must validate
and separately attest any receipt before it can participate in a gate.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Protocol, Sequence


SAFE_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
COMMIT_SHA = re.compile(r"^[0-9a-f]{40}$")
SHA256_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")


class SandboxContractError(ValueError):
    """Raised when a sandbox request or receipt violates the runtime contract."""


def _require_identifier(name: str, value: str) -> None:
    if not isinstance(value, str) or not SAFE_IDENTIFIER.fullmatch(value):
        raise SandboxContractError(f"{name} is invalid")


def _require_aware(name: str, value: datetime) -> None:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise SandboxContractError(f"{name} must be timezone-aware")


def _require_digest(name: str, value: str) -> None:
    if not isinstance(value, str) or not SHA256_DIGEST.fullmatch(value):
        raise SandboxContractError(f"{name} must be a sha256 digest")


def command_digest(command: Sequence[str]) -> str:
    """Return an unambiguous digest for an argv-style command sequence."""

    if not command or any(not isinstance(item, str) or not item for item in command):
        raise SandboxContractError("command must contain nonempty argv strings")
    payload = b"\0".join(item.encode("utf-8") for item in command)
    return "sha256:" + hashlib.sha256(payload).hexdigest()


@dataclass(frozen=True)
class SandboxRequest:
    """Controller-bound request handed to a non-authoritative sandbox runtime."""

    request_id: str
    task_id: str
    lease_id: str
    role_id: str
    source_commit: str
    workspace_digest: str
    command: tuple[str, ...]
    environment_digest: str
    timeout_seconds: int
    expected_runner_identity: str

    def __post_init__(self) -> None:
        _require_identifier("request_id", self.request_id)
        _require_identifier("task_id", self.task_id)
        _require_identifier("lease_id", self.lease_id)
        _require_identifier("role_id", self.role_id)
        _require_identifier("expected_runner_identity", self.expected_runner_identity)
        if not isinstance(self.source_commit, str) or not COMMIT_SHA.fullmatch(self.source_commit):
            raise SandboxContractError("source_commit must be an exact 40-character commit SHA")
        _require_digest("workspace_digest", self.workspace_digest)
        command_digest(self.command)
        _require_digest("environment_digest", self.environment_digest)
        if isinstance(self.timeout_seconds, bool) or not isinstance(self.timeout_seconds, int):
            raise SandboxContractError("timeout_seconds must be an integer")
        if self.timeout_seconds < 1 or self.timeout_seconds > 3600:
            raise SandboxContractError("timeout_seconds must be between 1 and 3600")

    @property
    def command_digest(self) -> str:
        return command_digest(self.command)

    @property
    def request_digest(self) -> str:
        fields = (
            self.request_id,
            self.task_id,
            self.lease_id,
            self.role_id,
            self.source_commit,
            self.workspace_digest,
            self.command_digest,
            self.environment_digest,
            str(self.timeout_seconds),
            self.expected_runner_identity,
        )
        payload = b"\0".join(item.encode("utf-8") for item in fields)
        return "sha256:" + hashlib.sha256(payload).hexdigest()


@dataclass(frozen=True)
class SandboxReceipt:
    """Untrusted execution receipt returned by a sandbox implementation."""

    request_id: str
    task_id: str
    lease_id: str
    role_id: str
    source_commit: str
    workspace_digest: str
    command_digest: str
    environment_digest: str
    runner_identity: str
    sandbox_id: str
    started_at: datetime
    finished_at: datetime
    exit_code: int | None
    timed_out: bool
    stdout_digest: str
    stderr_digest: str

    def __post_init__(self) -> None:
        for name in ("request_id", "task_id", "lease_id", "role_id", "runner_identity", "sandbox_id"):
            _require_identifier(name, getattr(self, name))
        if not isinstance(self.source_commit, str) or not COMMIT_SHA.fullmatch(self.source_commit):
            raise SandboxContractError("receipt source_commit is invalid")
        _require_digest("workspace_digest", self.workspace_digest)
        _require_digest("command_digest", self.command_digest)
        _require_digest("environment_digest", self.environment_digest)
        _require_digest("stdout_digest", self.stdout_digest)
        _require_digest("stderr_digest", self.stderr_digest)
        _require_aware("started_at", self.started_at)
        _require_aware("finished_at", self.finished_at)
        if self.exit_code is not None and (isinstance(self.exit_code, bool) or not isinstance(self.exit_code, int)):
            raise SandboxContractError("exit_code must be an integer or null")
        if not isinstance(self.timed_out, bool):
            raise SandboxContractError("timed_out must be boolean")


@dataclass(frozen=True)
class ValidatedSandboxReceipt:
    """A receipt that passed deterministic binding checks.

    This is still not Factory Evidence. In particular it intentionally contains
    no signature-valid flag, no Controller authority, and no state transition
    capability.
    """

    receipt: SandboxReceipt
    request_digest: str
    verified_at: datetime


class SandboxAdapter(Protocol):
    """Narrow seam that future Phalanx-derived runtimes must implement."""

    async def execute(self, request: SandboxRequest) -> SandboxReceipt:
        """Execute exactly the supplied request and return an untrusted receipt."""
        ...


def validate_sandbox_receipt(
    request: SandboxRequest,
    receipt: SandboxReceipt,
    *,
    now: datetime | None = None,
) -> ValidatedSandboxReceipt:
    """Fail closed unless a successful receipt is exactly bound to its request."""

    now = now or datetime.now(timezone.utc)
    _require_aware("now", now)

    exact_bindings = {
        "request_id": (receipt.request_id, request.request_id),
        "task_id": (receipt.task_id, request.task_id),
        "lease_id": (receipt.lease_id, request.lease_id),
        "role_id": (receipt.role_id, request.role_id),
        "source_commit": (receipt.source_commit, request.source_commit),
        "workspace_digest": (receipt.workspace_digest, request.workspace_digest),
        "command_digest": (receipt.command_digest, request.command_digest),
        "environment_digest": (receipt.environment_digest, request.environment_digest),
        "runner_identity": (receipt.runner_identity, request.expected_runner_identity),
    }
    for field, (actual, expected) in exact_bindings.items():
        if actual != expected:
            raise SandboxContractError(f"receipt {field} does not match request")

    if receipt.finished_at < receipt.started_at:
        raise SandboxContractError("receipt finished_at precedes started_at")
    if receipt.started_at > now or receipt.finished_at > now:
        raise SandboxContractError("future-dated sandbox receipt is invalid")

    elapsed = (receipt.finished_at - receipt.started_at).total_seconds()
    if elapsed > request.timeout_seconds:
        raise SandboxContractError("sandbox execution exceeded the authorized timeout")
    if receipt.timed_out:
        raise SandboxContractError("timed-out sandbox execution cannot verify work")
    if receipt.exit_code != 0:
        raise SandboxContractError("sandbox execution must exit zero to verify work")

    return ValidatedSandboxReceipt(
        receipt=receipt,
        request_digest=request.request_digest,
        verified_at=now,
    )
