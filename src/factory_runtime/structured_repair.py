"""Provider-neutral, structured AI repair strategy.

The model never receives a shell, Git credentials, or direct filesystem access.
It sees only redacted diagnostics, a bounded safe-file inventory, and sanitized
contents of files it explicitly requests. It may then propose literal
find-and-replace edits only against files it previously read.

The enclosing BoundedCIRepairController remains authoritative for reproduction,
attempt limits, workspace isolation, and the final exact-command verification.
This module can never declare a repair successful.
"""

from __future__ import annotations

import hashlib
import os
import posixpath
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from .diagnostics import RuntimeDiagnostics, sanitize_text_for_model
from .repair import RepairAction, RepairContext, RepairStrategy


class StructuredRepairError(RuntimeError):
    """Raised when a model decision or source-context operation violates policy."""


class StructuredRepairModelEscalation(StructuredRepairError):
    """Raised when the model explicitly declines to propose a safe repair."""


@dataclass(frozen=True)
class StructuredRepairPolicy:
    max_model_turns: int = 4
    max_read_paths_per_turn: int = 4
    max_inventory_paths: int = 500
    max_file_bytes: int = 64 * 1024
    max_file_context_chars: int = 32768
    max_total_context_chars: int = 128 * 1024
    max_edits: int = 8
    max_old_text_chars: int = 16384
    max_new_text_chars: int = 32768
    max_total_edit_chars: int = 128 * 1024
    denied_prefixes: tuple[str, ...] = (".git/", ".github/workflows/")
    denied_basenames: tuple[str, ...] = (
        ".env",
        "credentials",
        "credentials.json",
        "secrets.json",
        "secrets.yml",
        "secrets.yaml",
        "id_rsa",
        "id_dsa",
        "id_ed25519",
    )
    denied_suffixes: tuple[str, ...] = (".pem", ".key", ".p12", ".pfx", ".jks")
    denied_lockfiles: tuple[str, ...] = (
        "package-lock.json",
        "pnpm-lock.yaml",
        "yarn.lock",
        "poetry.lock",
        "uv.lock",
        "Pipfile.lock",
        "Cargo.lock",
    )

    def __post_init__(self) -> None:
        bounds = (
            ("max_model_turns", self.max_model_turns, 1, 8),
            ("max_read_paths_per_turn", self.max_read_paths_per_turn, 1, 8),
            ("max_inventory_paths", self.max_inventory_paths, 1, 2000),
            ("max_file_bytes", self.max_file_bytes, 1024, 1024 * 1024),
            ("max_file_context_chars", self.max_file_context_chars, 512, 131072),
            ("max_total_context_chars", self.max_total_context_chars, 1024, 512 * 1024),
            ("max_edits", self.max_edits, 1, 32),
            ("max_old_text_chars", self.max_old_text_chars, 1, 65536),
            ("max_new_text_chars", self.max_new_text_chars, 0, 131072),
            ("max_total_edit_chars", self.max_total_edit_chars, 1, 512 * 1024),
        )
        for name, value, low, high in bounds:
            if isinstance(value, bool) or not isinstance(value, int) or value < low or value > high:
                raise StructuredRepairError(f"{name} must be between {low} and {high}")


@dataclass(frozen=True)
class RepairFileContext:
    path: str
    content_digest: str
    content: str
    redaction_count: int
    truncated: bool


@dataclass(frozen=True)
class RepairModelTurn:
    repair_id: str
    attempt_number: int
    turn_number: int
    original_command: tuple[str, ...]
    stdout_excerpt: str
    stderr_excerpt: str
    diagnostic_redaction_count: int
    inventory: tuple[str, ...]
    files: tuple[RepairFileContext, ...]


@dataclass(frozen=True)
class ReadFilesDecision:
    paths: tuple[str, ...]


@dataclass(frozen=True)
class LiteralReplaceEdit:
    path: str
    old_text: str
    new_text: str


@dataclass(frozen=True)
class ApplyEditsDecision:
    summary: str
    edits: tuple[LiteralReplaceEdit, ...]


@dataclass(frozen=True)
class EscalateDecision:
    reason: str


RepairModelDecision = ReadFilesDecision | ApplyEditsDecision | EscalateDecision


class RepairModel(Protocol):
    async def decide(self, turn: RepairModelTurn) -> RepairModelDecision:
        """Return one structured read/edit/escalate decision."""
        ...


def _normalized_path(raw: str) -> str:
    if not isinstance(raw, str) or not raw or "\\" in raw or raw.startswith("/"):
        raise StructuredRepairError("repair path must be a normalized repo-relative POSIX path")
    normalized = posixpath.normpath(raw)
    if normalized != raw or normalized in {".", ".."} or normalized.startswith("../"):
        raise StructuredRepairError("repair path must be a normalized repo-relative POSIX path")
    return normalized


def _is_denied(path: str, policy: StructuredRepairPolicy) -> bool:
    lowered = path.lower()
    name = posixpath.basename(path)
    lowered_name = name.lower()
    if any(lowered.startswith(prefix.lower()) for prefix in policy.denied_prefixes):
        return True
    if lowered_name == ".env" or lowered_name.startswith(".env."):
        return True
    if lowered_name in {item.lower() for item in policy.denied_basenames}:
        return True
    if name in policy.denied_lockfiles:
        return True
    if any(lowered_name.endswith(suffix.lower()) for suffix in policy.denied_suffixes):
        return True
    return False


def _safe_file(workspace: Path, path: str, policy: StructuredRepairPolicy) -> Path:
    workspace = workspace.resolve()
    normalized = _normalized_path(path)
    if _is_denied(normalized, policy):
        raise StructuredRepairError(f"repair path is denied by policy: {normalized}")

    cursor = workspace
    for part in Path(normalized).parts:
        cursor = cursor / part
        if cursor.is_symlink():
            raise StructuredRepairError(f"repair path contains a symlink component: {normalized}")

    if not cursor.is_file():
        raise StructuredRepairError(f"repair path is not a regular file: {normalized}")
    try:
        resolved = cursor.resolve(strict=True)
        resolved.relative_to(workspace)
    except (OSError, ValueError) as exc:
        raise StructuredRepairError("repair path escaped workspace") from exc
    if resolved != cursor:
        raise StructuredRepairError(f"repair path resolution is not direct: {normalized}")
    return cursor


def _inventory(workspace: Path, policy: StructuredRepairPolicy) -> tuple[str, ...]:
    workspace = workspace.resolve()
    paths: list[str] = []
    for item in sorted(workspace.rglob("*"), key=lambda p: p.relative_to(workspace).as_posix()):
        if item.is_symlink() or not item.is_file():
            continue
        relative = item.relative_to(workspace).as_posix()
        if _is_denied(relative, policy):
            continue
        try:
            _safe_file(workspace, relative, policy)
            size = item.stat().st_size
        except (OSError, StructuredRepairError):
            continue
        if size > policy.max_file_bytes:
            continue
        paths.append(relative)
        if len(paths) > policy.max_inventory_paths:
            raise StructuredRepairError("safe source inventory exceeded configured path cap")
    return tuple(paths)


def _load_file_context(
    workspace: Path,
    path: str,
    policy: StructuredRepairPolicy,
) -> RepairFileContext:
    file_path = _safe_file(workspace, path, policy)
    raw = file_path.read_bytes()
    if len(raw) > policy.max_file_bytes:
        raise StructuredRepairError(f"source file exceeds configured byte cap: {path}")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise StructuredRepairError(f"source file is not UTF-8 text: {path}") from exc
    sanitized = sanitize_text_for_model(text, max_chars=policy.max_file_context_chars)
    return RepairFileContext(
        path=path,
        content_digest="sha256:" + hashlib.sha256(raw).hexdigest(),
        content=sanitized.text,
        redaction_count=sanitized.redaction_count,
        truncated=sanitized.truncated,
    )


def _read_current_text(
    workspace: Path,
    context: RepairFileContext,
    policy: StructuredRepairPolicy,
) -> str:
    file_path = _safe_file(workspace, context.path, policy)
    raw = file_path.read_bytes()
    digest = "sha256:" + hashlib.sha256(raw).hexdigest()
    if digest != context.content_digest:
        raise StructuredRepairError(f"source file changed after model read: {context.path}")
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise StructuredRepairError(f"source file is no longer UTF-8: {context.path}") from exc


def _atomic_replace_text(target: Path, content: str, mode: int) -> None:
    temp_name: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            newline="",
            dir=target.parent,
            prefix=f".{target.name}.factory-repair-",
            delete=False,
        ) as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
            temp_name = handle.name
        temp_path = Path(temp_name)
        os.chmod(temp_path, mode & 0o777)
        os.replace(temp_path, target)
        temp_name = None
    finally:
        if temp_name is not None:
            Path(temp_name).unlink(missing_ok=True)


class StructuredAIRepairStrategy(RepairStrategy):
    """Bounded read/replace model strategy for a disposable repair workspace."""

    def __init__(
        self,
        model: RepairModel,
        policy: StructuredRepairPolicy | None = None,
    ) -> None:
        self.model = model
        self.policy = policy or StructuredRepairPolicy()

    async def apply(self, workspace: Path, context: RepairContext) -> RepairAction:
        diagnostics: RuntimeDiagnostics | None = context.previous_failure.diagnostics
        if diagnostics is None:
            raise StructuredRepairError("repair model requires sanitized runtime diagnostics")

        workspace = workspace.resolve()
        inventory = _inventory(workspace, self.policy)
        read_files: dict[str, RepairFileContext] = {}
        total_context_chars = 0

        for turn_number in range(1, self.policy.max_model_turns + 1):
            turn = RepairModelTurn(
                repair_id=context.repair_id,
                attempt_number=context.attempt_number,
                turn_number=turn_number,
                original_command=context.original_command,
                stdout_excerpt=diagnostics.stdout_excerpt,
                stderr_excerpt=diagnostics.stderr_excerpt,
                diagnostic_redaction_count=diagnostics.redaction_count,
                inventory=inventory,
                files=tuple(read_files[path] for path in sorted(read_files)),
            )
            decision = await self.model.decide(turn)

            if isinstance(decision, ReadFilesDecision):
                if not decision.paths or len(decision.paths) > self.policy.max_read_paths_per_turn:
                    raise StructuredRepairError("model requested an invalid number of source files")
                if len(set(decision.paths)) != len(decision.paths):
                    raise StructuredRepairError("model requested duplicate source paths")
                for raw_path in decision.paths:
                    path = _normalized_path(raw_path)
                    if path not in inventory:
                        raise StructuredRepairError(f"model requested unavailable source path: {path}")
                    if path in read_files:
                        raise StructuredRepairError(f"model requested an already-read source path: {path}")
                    file_context = _load_file_context(workspace, path, self.policy)
                    total_context_chars += len(file_context.content)
                    if total_context_chars > self.policy.max_total_context_chars:
                        raise StructuredRepairError("model source context exceeded configured total cap")
                    read_files[path] = file_context
                continue

            if isinstance(decision, EscalateDecision):
                if not isinstance(decision.reason, str) or not decision.reason.strip() or len(decision.reason) > 512:
                    raise StructuredRepairError("model escalation reason is invalid")
                raise StructuredRepairModelEscalation(decision.reason.strip())

            if not isinstance(decision, ApplyEditsDecision):
                raise StructuredRepairError("repair model returned an unsupported decision type")
            if not isinstance(decision.summary, str) or not decision.summary.strip() or len(decision.summary) > 512:
                raise StructuredRepairError("repair proposal summary is invalid")
            if not decision.edits or len(decision.edits) > self.policy.max_edits:
                raise StructuredRepairError("repair proposal contains an invalid number of edits")

            staged: dict[str, str] = {}
            original_modes: dict[str, int] = {}
            total_edit_chars = 0
            for edit in decision.edits:
                if not isinstance(edit, LiteralReplaceEdit):
                    raise StructuredRepairError("repair proposal contains an invalid edit object")
                path = _normalized_path(edit.path)
                if path not in read_files:
                    raise StructuredRepairError(f"model may edit only files it previously read: {path}")
                if not isinstance(edit.old_text, str) or not edit.old_text:
                    raise StructuredRepairError("literal replacement old_text must be nonempty")
                if not isinstance(edit.new_text, str):
                    raise StructuredRepairError("literal replacement new_text must be a string")
                if len(edit.old_text) > self.policy.max_old_text_chars:
                    raise StructuredRepairError("literal replacement old_text exceeds configured cap")
                if len(edit.new_text) > self.policy.max_new_text_chars:
                    raise StructuredRepairError("literal replacement new_text exceeds configured cap")
                if "[REDACTED" in edit.old_text or "[REDACTED" in edit.new_text:
                    raise StructuredRepairError("model may not edit through redacted source material")
                if edit.old_text == edit.new_text:
                    raise StructuredRepairError("literal replacement must change file content")

                if path not in staged:
                    staged[path] = _read_current_text(workspace, read_files[path], self.policy)
                    original_modes[path] = os.stat(_safe_file(workspace, path, self.policy), follow_symlinks=False).st_mode
                current = staged[path]
                matches = current.count(edit.old_text)
                if matches != 1:
                    raise StructuredRepairError(
                        f"literal replacement must match exactly once in {path}; found {matches}"
                    )
                total_edit_chars += len(edit.old_text) + len(edit.new_text)
                if total_edit_chars > self.policy.max_total_edit_chars:
                    raise StructuredRepairError("repair proposal exceeds configured total edit cap")
                staged[path] = current.replace(edit.old_text, edit.new_text, 1)

            # All proposal checks complete before any workspace mutation.
            for path, new_content in staged.items():
                target = _safe_file(workspace, path, self.policy)
                _atomic_replace_text(target, new_content, original_modes[path])

            return RepairAction(summary=decision.summary.strip())

        raise StructuredRepairError("repair model exhausted its bounded turn budget without an edit")
