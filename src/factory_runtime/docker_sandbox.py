"""Hardened Docker implementation of the Factory sandbox adapter.

This runner is intentionally a *verification* sandbox, not a dependency
provisioner. Images must already exist locally and be pinned by digest. The
container runs with networking disabled, a read-only root filesystem, dropped
capabilities, no-new-privileges, and bounded resources. The source workspace is
copied to a disposable host directory before it is mounted read/write, so
untrusted verification commands cannot mutate the authoritative checkout.
"""

from __future__ import annotations

import asyncio
import hashlib
import os
import re
import shutil
import stat
import tempfile
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Protocol

from .sandbox import SandboxContractError, SandboxReceipt, SandboxRequest


PINNED_IMAGE = re.compile(r"^[^\s@]+@sha256:[0-9a-f]{64}$")
CONTAINER_ID = re.compile(r"^[0-9a-f]{12,64}$")
EXCLUDED_WORKSPACE_NAMES = {".git", ".pytest_cache", "__pycache__"}
EMPTY_DIGEST = "sha256:" + hashlib.sha256(b"").hexdigest()
_POLICY_VERSION = "factory-docker-sandbox-v1"


class SandboxExecutionError(RuntimeError):
    """Raised when the sandbox cannot execute a request safely."""


class ProcessTimeout(TimeoutError):
    """Raised when an external process exceeds its wall-clock limit."""


class ProcessOutputLimit(RuntimeError):
    """Raised when a subprocess exceeds the bounded output allowance."""


@dataclass(frozen=True)
class ProcessResult:
    returncode: int
    stdout: bytes = b""
    stderr: bytes = b""


class ProcessRunner(Protocol):
    async def run(self, argv: tuple[str, ...], *, timeout_seconds: int) -> ProcessResult:
        ...


class AsyncioProcessRunner:
    """Subprocess runner with sanitized environment, timeout, and output caps."""

    def __init__(self, *, max_output_bytes: int = 4 * 1024 * 1024) -> None:
        if max_output_bytes < 1024:
            raise ValueError("max_output_bytes must be at least 1024")
        self.max_output_bytes = max_output_bytes

    async def run(self, argv: tuple[str, ...], *, timeout_seconds: int) -> ProcessResult:
        env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin")}
        proc = await asyncio.create_subprocess_exec(
            *argv,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=env,
        )
        assert proc.stdout is not None and proc.stderr is not None

        async def read_capped(stream: asyncio.StreamReader) -> bytes:
            data = bytearray()
            while True:
                chunk = await stream.read(65536)
                if not chunk:
                    return bytes(data)
                data.extend(chunk)
                if len(data) > self.max_output_bytes:
                    raise ProcessOutputLimit("subprocess output exceeded configured cap")

        stdout_task = asyncio.create_task(read_capped(proc.stdout))
        stderr_task = asyncio.create_task(read_capped(proc.stderr))
        wait_task = asyncio.create_task(proc.wait())
        tasks = (wait_task, stdout_task, stderr_task)
        try:
            returncode, stdout, stderr = await asyncio.wait_for(
                asyncio.gather(*tasks), timeout=timeout_seconds
            )
            return ProcessResult(returncode=returncode, stdout=stdout, stderr=stderr)
        except asyncio.TimeoutError as exc:
            proc.kill()
            await proc.wait()
            for task in tasks:
                if not task.done():
                    task.cancel()
            raise ProcessTimeout(f"process exceeded {timeout_seconds}s") from exc
        except ProcessOutputLimit:
            proc.kill()
            await proc.wait()
            for task in tasks:
                if not task.done():
                    task.cancel()
            raise


@dataclass(frozen=True)
class DockerSandboxPolicy:
    """Immutable execution policy whose digest is bound into SandboxRequest."""

    image_ref: str
    runner_identity: str = "factory_docker_sandbox_v1"
    docker_executable: str = "docker"
    memory: str = "2g"
    cpus: str = "2"
    pids_limit: int = 256
    user: str = "65532:65532"
    tmpfs_size: str = "256m"

    def __post_init__(self) -> None:
        if not PINNED_IMAGE.fullmatch(self.image_ref):
            raise SandboxContractError("Docker sandbox image must be pinned by sha256 digest")
        if not self.runner_identity or any(ch.isspace() for ch in self.runner_identity):
            raise SandboxContractError("runner_identity is invalid")
        if not self.docker_executable or any(ch.isspace() for ch in self.docker_executable):
            raise SandboxContractError("docker_executable is invalid")
        if isinstance(self.pids_limit, bool) or not isinstance(self.pids_limit, int) or self.pids_limit < 1:
            raise SandboxContractError("pids_limit must be a positive integer")

    @property
    def environment_digest(self) -> str:
        fields = (
            _POLICY_VERSION,
            self.image_ref,
            self.runner_identity,
            self.memory,
            self.cpus,
            str(self.pids_limit),
            self.user,
            self.tmpfs_size,
            "network=none",
            "rootfs=readonly",
            "capabilities=drop-all",
            "no-new-privileges=true",
            "workspace=disposable-rw-copy",
        )
        payload = b"\0".join(item.encode("utf-8") for item in fields)
        return "sha256:" + hashlib.sha256(payload).hexdigest()


def workspace_tree_digest(root: Path) -> str:
    """Hash the exact verification workspace without following symlinks.

    Git metadata and interpreter/test caches are excluded because they are not
    verification inputs. Relative path, entry type, executable bit, content,
    and symlink target are bound into the digest.
    """

    root = root.resolve()
    if not root.is_dir():
        raise SandboxExecutionError("workspace must be an existing directory")

    hasher = hashlib.sha256()
    entries = sorted(root.rglob("*"), key=lambda p: p.relative_to(root).as_posix())
    for path in entries:
        relative = path.relative_to(root)
        if any(part in EXCLUDED_WORKSPACE_NAMES for part in relative.parts):
            continue
        rel = relative.as_posix()
        mode = path.lstat().st_mode
        if stat.S_ISDIR(mode):
            continue
        if stat.S_ISLNK(mode):
            target = os.readlink(path)
            record = f"L\0{rel}\0{target}\n".encode("utf-8")
            hasher.update(record)
            continue
        if not stat.S_ISREG(mode):
            raise SandboxExecutionError(f"unsupported workspace entry: {rel}")
        executable = "1" if mode & 0o111 else "0"
        content_digest = hashlib.sha256(path.read_bytes()).hexdigest()
        record = f"F\0{rel}\0{executable}\0{content_digest}\n".encode("utf-8")
        hasher.update(record)
    return "sha256:" + hasher.hexdigest()


def _copy_workspace(source: Path, destination: Path) -> None:
    def ignore(_directory: str, names: list[str]) -> set[str]:
        return {name for name in names if name in EXCLUDED_WORKSPACE_NAMES}

    shutil.copytree(source, destination, symlinks=True, ignore=ignore)


def _make_copy_writable(root: Path) -> None:
    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            continue
        if path.is_dir():
            path.chmod(0o777)
        elif path.is_file():
            original = path.stat().st_mode
            path.chmod(0o777 if original & 0o111 else 0o666)
    root.chmod(0o777)


def _digest_bytes(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


class DockerSandboxAdapter:
    """Execute one bound verification command inside a disposable container."""

    def __init__(
        self,
        workspace: Path,
        policy: DockerSandboxPolicy,
        *,
        process_runner: ProcessRunner | None = None,
    ) -> None:
        self.workspace = workspace
        self.policy = policy
        self.process_runner = process_runner or AsyncioProcessRunner()

    async def execute(self, request: SandboxRequest) -> SandboxReceipt:
        if request.expected_runner_identity != self.policy.runner_identity:
            raise SandboxExecutionError("request runner identity does not match Docker sandbox policy")
        if request.environment_digest != self.policy.environment_digest:
            raise SandboxExecutionError("request environment digest does not match Docker sandbox policy")

        source_digest = workspace_tree_digest(self.workspace)
        if source_digest != request.workspace_digest:
            raise SandboxExecutionError("workspace digest does not match authorized request")

        image_check = await self.process_runner.run(
            (self.policy.docker_executable, "image", "inspect", self.policy.image_ref),
            timeout_seconds=30,
        )
        if image_check.returncode != 0:
            raise SandboxExecutionError("pinned sandbox image is not available locally")

        with tempfile.TemporaryDirectory(prefix="factory-sandbox-") as temp_dir:
            copied_workspace = Path(temp_dir) / "workspace"
            _copy_workspace(self.workspace, copied_workspace)
            if workspace_tree_digest(copied_workspace) != request.workspace_digest:
                raise SandboxExecutionError("workspace changed while preparing disposable sandbox copy")
            _make_copy_writable(copied_workspace)

            container_name = f"factory-sandbox-{uuid.uuid4().hex[:12]}"
            create_args = self._create_args(request, copied_workspace, container_name)
            create_result = await self.process_runner.run(create_args, timeout_seconds=60)
            if create_result.returncode != 0:
                raise SandboxExecutionError("Docker refused to create the verification sandbox")
            sandbox_id = create_result.stdout.decode("utf-8", errors="replace").strip()
            if not CONTAINER_ID.fullmatch(sandbox_id):
                await self._cleanup(container_name)
                raise SandboxExecutionError("Docker returned an invalid sandbox id")

            started_at = datetime.now(timezone.utc)
            timed_out = False
            stdout = b""
            stderr = b""
            exit_code: int | None = None
            try:
                try:
                    run_result = await self.process_runner.run(
                        (self.policy.docker_executable, "start", "--attach", sandbox_id),
                        timeout_seconds=request.timeout_seconds,
                    )
                    stdout = run_result.stdout
                    stderr = run_result.stderr
                except ProcessTimeout:
                    timed_out = True

                if not timed_out:
                    inspect_result = await self.process_runner.run(
                        (
                            self.policy.docker_executable,
                            "inspect",
                            "--format={{.State.ExitCode}}",
                            sandbox_id,
                        ),
                        timeout_seconds=30,
                    )
                    if inspect_result.returncode != 0:
                        raise SandboxExecutionError("could not read sandbox exit code")
                    try:
                        exit_code = int(inspect_result.stdout.decode().strip())
                    except ValueError as exc:
                        raise SandboxExecutionError("sandbox exit code was invalid") from exc
            finally:
                finished_at = datetime.now(timezone.utc)
                await self._cleanup(sandbox_id)

        return SandboxReceipt(
            request_id=request.request_id,
            task_id=request.task_id,
            lease_id=request.lease_id,
            role_id=request.role_id,
            source_commit=request.source_commit,
            workspace_digest=request.workspace_digest,
            command_digest=request.command_digest,
            environment_digest=request.environment_digest,
            runner_identity=self.policy.runner_identity,
            sandbox_id=sandbox_id,
            started_at=started_at,
            finished_at=finished_at,
            exit_code=exit_code,
            timed_out=timed_out,
            stdout_digest=_digest_bytes(stdout),
            stderr_digest=_digest_bytes(stderr),
        )

    def _create_args(
        self,
        request: SandboxRequest,
        copied_workspace: Path,
        container_name: str,
    ) -> tuple[str, ...]:
        mount = f"type=bind,src={copied_workspace},dst=/workspace,rw"
        return (
            self.policy.docker_executable,
            "create",
            "--pull=never",
            "--name",
            container_name,
            "--network=none",
            "--read-only",
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges:true",
            "--memory",
            self.policy.memory,
            "--memory-swap",
            self.policy.memory,
            "--cpus",
            self.policy.cpus,
            "--pids-limit",
            str(self.policy.pids_limit),
            "--ulimit",
            "nofile=4096:4096",
            "--ulimit",
            "nproc=512:512",
            "--user",
            self.policy.user,
            f"--tmpfs=/tmp:rw,nosuid,nodev,size={self.policy.tmpfs_size}",
            "--mount",
            mount,
            "--workdir",
            "/workspace",
            "--env",
            "HOME=/tmp",
            "--env",
            "CI=true",
            "--env",
            "GIT_CONFIG_COUNT=1",
            "--env",
            "GIT_CONFIG_KEY_0=safe.directory",
            "--env",
            "GIT_CONFIG_VALUE_0=/workspace",
            "--label",
            "factory.sandbox=true",
            "--label",
            f"factory.request_id={request.request_id}",
            self.policy.image_ref,
            *request.command,
        )

    async def _cleanup(self, sandbox_id: str) -> None:
        try:
            await self.process_runner.run(
                (self.policy.docker_executable, "rm", "-f", sandbox_id),
                timeout_seconds=30,
            )
        except Exception:
            # Runtime cleanup is best effort here. Independent orphan reaping is
            # a separate control and must not turn a completed receipt into a
            # false success or false failure.
            pass
