"""Bounded redacted runtime diagnostics below the Factory trust boundary.

Raw stdout/stderr are never stored by this module. A configured capture receives
bounded process output, verifies its digests against the sandbox receipt,
redacts common secret forms, truncates deterministically, and stores only a
one-shot sanitized diagnostic bundle keyed to the exact SandboxRequest digest.

Diagnostics are advisory only. They are not Factory Evidence, do not affect
state authority, and cannot promote a failed sandbox receipt to success.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from typing import Protocol

from .sandbox import SandboxReceipt, SandboxRequest


_SANITIZER_VERSION = "factory-redacted-diagnostics-v1"
_TRUNCATION_MARKER = "\n...[TRUNCATED BY FACTORY DIAGNOSTICS]...\n"


class DiagnosticCaptureError(RuntimeError):
    """Raised when a diagnostic bundle cannot be produced or consumed safely."""


_SECRET_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (
        re.compile(
            r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----",
            re.DOTALL,
        ),
        "[REDACTED_PRIVATE_KEY]",
    ),
    (
        re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,})\b"),
        "[REDACTED_GITHUB_TOKEN]",
    ),
    (
        re.compile(r"\bsk-(?:ant-)?[A-Za-z0-9_-]{16,}\b"),
        "[REDACTED_API_KEY]",
    ),
    (
        re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
        "[REDACTED_SLACK_TOKEN]",
    ),
    (
        re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
        "[REDACTED_AWS_ACCESS_KEY]",
    ),
    (
        re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"),
        "[REDACTED_JWT]",
    ),
    (
        re.compile(r"(?i)\b(?:Bearer|Basic)\s+[A-Za-z0-9+/=._~:-]{8,}"),
        "[REDACTED_AUTHORIZATION]",
    ),
    (
        re.compile(r"(?i)\b([a-z][a-z0-9+.-]*://)([^/\s:@]+):([^@\s/]+)@"),
        r"\1[REDACTED_CREDENTIALS]@",
    ),
    (
        re.compile(
            r"(?i)([\"']?(?:password|passwd|pwd|token|secret|api[_-]?key|access[_-]?key|client[_-]?secret|authorization)[\"']?\s*[:=]\s*)([\"']?)([^\"'\s,;]+)([\"']?)"
        ),
        r"\1[REDACTED]",
    ),
)


def _digest_bytes(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _normalize_string(text: str) -> str:
    return "".join(
        ch
        if ch in "\n\t" or ord(ch) >= 32
        else "\ufffd"
        for ch in text
    )


def _normalize_text(value: bytes) -> str:
    return _normalize_string(value.decode("utf-8", errors="replace"))


def _redact(text: str) -> tuple[str, int]:
    count = 0
    for pattern, replacement in _SECRET_PATTERNS:
        text, replaced = pattern.subn(replacement, text)
        count += replaced
    return text, count


def _truncate(text: str, max_chars: int) -> tuple[str, bool]:
    if len(text) <= max_chars:
        return text, False
    marker = _TRUNCATION_MARKER
    head = max(128, max_chars // 4)
    tail = max_chars - head - len(marker)
    if tail < 128:
        head = max(64, (max_chars - len(marker)) // 2)
        tail = max_chars - head - len(marker)
    return text[:head] + marker + text[-tail:], True


@dataclass(frozen=True)
class SanitizedModelText:
    """Bounded text safe enough for model context; never authoritative evidence."""

    text: str
    redaction_count: int
    truncated: bool
    sanitizer_version: str = _SANITIZER_VERSION


def sanitize_text_for_model(text: str, *, max_chars: int = 32768) -> SanitizedModelText:
    """Redact common secret forms and bound arbitrary text before model exposure."""

    if not isinstance(text, str):
        raise TypeError("model context text must be a string")
    if isinstance(max_chars, bool) or not isinstance(max_chars, int):
        raise ValueError("max_chars must be an integer")
    if max_chars < 512 or max_chars > 131072:
        raise ValueError("max_chars must be between 512 and 131072")
    redacted, count = _redact(_normalize_string(text))
    bounded, truncated = _truncate(redacted, max_chars)
    return SanitizedModelText(
        text=bounded,
        redaction_count=count,
        truncated=truncated,
    )


@dataclass(frozen=True)
class RuntimeDiagnostics:
    """One-shot sanitized diagnostics bound to a SandboxRequest and output digests."""

    request_digest: str
    stdout_digest: str
    stderr_digest: str
    stdout_excerpt: str
    stderr_excerpt: str
    redaction_count: int
    stdout_truncated: bool
    stderr_truncated: bool
    sanitizer_version: str = _SANITIZER_VERSION


class DiagnosticSource(Protocol):
    def take(self, request: SandboxRequest, receipt: SandboxReceipt) -> RuntimeDiagnostics:
        """Consume the one-shot diagnostic bundle for this exact request."""
        ...


class DiagnosticCapture(DiagnosticSource, Protocol):
    def capture(
        self,
        request: SandboxRequest,
        receipt: SandboxReceipt,
        stdout: bytes,
        stderr: bytes,
    ) -> None:
        """Sanitize bounded raw output and retain only the redacted bundle."""
        ...


class RedactedDiagnosticCapture:
    """In-memory one-shot capture that never retains raw process output."""

    def __init__(
        self,
        *,
        max_chars_per_stream: int = 6000,
        max_input_bytes: int = 4 * 1024 * 1024,
    ) -> None:
        if isinstance(max_chars_per_stream, bool) or not isinstance(max_chars_per_stream, int):
            raise ValueError("max_chars_per_stream must be an integer")
        if max_chars_per_stream < 512 or max_chars_per_stream > 32768:
            raise ValueError("max_chars_per_stream must be between 512 and 32768")
        if isinstance(max_input_bytes, bool) or not isinstance(max_input_bytes, int):
            raise ValueError("max_input_bytes must be an integer")
        if max_input_bytes < 1024 or max_input_bytes > 16 * 1024 * 1024:
            raise ValueError("max_input_bytes must be between 1024 and 16777216")
        self.max_chars_per_stream = max_chars_per_stream
        self.max_input_bytes = max_input_bytes
        self._items: dict[str, RuntimeDiagnostics] = {}

    def capture(
        self,
        request: SandboxRequest,
        receipt: SandboxReceipt,
        stdout: bytes,
        stderr: bytes,
    ) -> None:
        if len(stdout) > self.max_input_bytes or len(stderr) > self.max_input_bytes:
            raise DiagnosticCaptureError("diagnostic input exceeded configured byte cap")
        stdout_digest = _digest_bytes(stdout)
        stderr_digest = _digest_bytes(stderr)
        if stdout_digest != receipt.stdout_digest or stderr_digest != receipt.stderr_digest:
            raise DiagnosticCaptureError("diagnostic output digests do not match sandbox receipt")
        key = request.request_digest
        if key in self._items:
            raise DiagnosticCaptureError("diagnostics already captured for this request")

        stdout_text, stdout_redactions = _redact(_normalize_text(stdout))
        stderr_text, stderr_redactions = _redact(_normalize_text(stderr))
        stdout_excerpt, stdout_truncated = _truncate(stdout_text, self.max_chars_per_stream)
        stderr_excerpt, stderr_truncated = _truncate(stderr_text, self.max_chars_per_stream)

        self._items[key] = RuntimeDiagnostics(
            request_digest=key,
            stdout_digest=stdout_digest,
            stderr_digest=stderr_digest,
            stdout_excerpt=stdout_excerpt,
            stderr_excerpt=stderr_excerpt,
            redaction_count=stdout_redactions + stderr_redactions,
            stdout_truncated=stdout_truncated,
            stderr_truncated=stderr_truncated,
        )

    def take(self, request: SandboxRequest, receipt: SandboxReceipt) -> RuntimeDiagnostics:
        key = request.request_digest
        item = self._items.get(key)
        if item is None:
            raise DiagnosticCaptureError("no diagnostic bundle exists for this request")
        if item.stdout_digest != receipt.stdout_digest or item.stderr_digest != receipt.stderr_digest:
            raise DiagnosticCaptureError("diagnostic bundle no longer matches sandbox receipt")
        del self._items[key]
        return item
