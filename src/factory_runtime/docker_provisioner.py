"""Docker-backed Python environment provisioner below the Factory trust boundary.

Provisioning is intentionally distinct from verification. This component may
use an operator-preconfigured egress-controlled Docker network while installing
hash-locked Python dependencies, then produces a local content-addressed image
for the hardened networkless verification sandbox.

V1 is deliberately narrow: only Python environments and the exact
``python -m pip install --require-hashes -r <repo-relative-file>`` shape emitted
by the deterministic detector are accepted. Node and other stacks fail closed
until their dependency handoff semantics are designed and tested.
"""

from __future__ import annotations

import hashlib
import math
import re
import shutil
import tempfile
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from .docker_sandbox import (
    AsyncioProcessRunner,
    ProcessOutputLimit,
    ProcessResult,
    ProcessRunner,
    ProcessTimeout,
    workspace_tree_digest,
)
from .environment import (
    EnvironmentSpec,
    ProvisionStep,
    ProvisioningReceipt,
    ProvisioningRequest,
)


CONTAINER_ID = re.compile(r"^[0-9a-f]{12,64}$")
IMAGE_ID = re.compile(r"^sha256:[0-9a-f]{64}$")
DOCKER_NETWORK_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
SAFE_RELATIVE_FILE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_./-]{0,255}$")
FORBIDDEN_NETWORK_NAMES = frozenset({"bridge", "host", "none", "default"})
EXCLUDED_WORKSPACE_NAMES = {".git", ".pytest_cache", "__pycache__"}
EMPTY_DIGEST = "sha256:" + hashlib.sha256(b"").hexdigest()


class ProvisioningExecutionError(RuntimeError):
    """Raised when the provisioner cannot safely attempt or complete a build."""


@dataclass(frozen=True)
class DockerProvisioningPolicy:
    """Operator-owned Docker policy for bounded dependency provisioning."""

    network_bindings: tuple[tuple[str, str], ...] = ()
    provisioner_identity: str = "factory_docker_provisioner_v1"
    docker_executable: str = "docker"
    memory: str = "2g"
    cpus: str = "2"
    pids_limit: int = 256

    def __post_init__(self) -> None:
        if not self.provisioner_identity or any(ch.isspace() for ch in self.provisioner_identity):
            raise ProvisioningExecutionError("provisioner_identity is invalid")
        if not self.docker_executable or any(ch.isspace() for ch in self.docker_executable):
            raise ProvisioningExecutionError("docker_executable is invalid")
        if isinstance(self.pids_limit, bool) or not isinstance(self.pids_limit, int) or self.pids_limit < 1:
            raise ProvisioningExecutionError("pids_limit must be a positive integer")

        policy_ids: set[str] = set()
        network_names: set[str] = set()
        for policy_id, network_name in self.network_bindings:
            if not policy_id or any(ch.isspace() for ch in policy_id):
                raise ProvisioningExecutionError("network policy id is invalid")
            if policy_id in policy_ids:
                raise ProvisioningExecutionError("duplicate network policy binding")
            if not DOCKER_NETWORK_NAME.fullmatch(network_name):
                raise ProvisioningExecutionError("Docker network name is invalid")
            if network_name.lower() in FORBIDDEN_NETWORK_NAMES:
                raise ProvisioningExecutionError(
                    "provisioning may not use Docker's unrestricted/default network names"
                )
            if network_name in network_names:
                raise ProvisioningExecutionError("one Docker network may not represent multiple policies")
            policy_ids.add(policy_id)
            network_names.add(network_name)

    def resolve_network(self, network_policy_id: str) -> str:
        network = dict(self.network_bindings).get(network_policy_id)
        if network is None:
            raise ProvisioningExecutionError(
                f"no Docker network is bound to egress policy {network_policy_id!r}"
            )
        return network


def _copy_workspace(source: Path, destination: Path) -> None:
    def ignore(_directory: str, names: list[str]) -> set[str]:
        return {name for name in names if name in EXCLUDED_WORKSPACE_NAMES}

    shutil.copytree(source, destination, symlinks=True, ignore=ignore)


def _digest_record(argv: tuple[str, ...], result: ProcessResult | None, *, timed_out: bool) -> bytes:
    hasher = hashlib.sha256()
    hasher.update(b"ARGV\0")
    hasher.update(b"\0".join(part.encode("utf-8") for part in argv))
    hasher.update(b"\0TIMEOUT\0" + (b"1" if timed_out else b"0"))
    if result is not None:
        hasher.update(b"\0RC\0" + str(result.returncode).encode("ascii"))
        hasher.update(b"\0STDOUT\0" + hashlib.sha256(result.stdout).digest())
        hasher.update(b"\0STDERR\0" + hashlib.sha256(result.stderr).digest())
    return hasher.digest()


def _valid_python_v1_step(step: ProvisionStep) -> bool:
    argv = step.argv
    if len(argv) != 7:
        return False
    if argv[:6] != ("python", "-m", "pip", "install", "--require-hashes", "-r"):
        return False
    requirements_file = argv[6]
    if (
        not SAFE_RELATIVE_FILE.fullmatch(requirements_file)
        or requirements_file.startswith("/")
        or ".." in Path(requirements_file).parts
    ):
        return False
    return step.network_required is True


class DockerEnvironmentProvisioner:
    """Build a content-addressed Python dependency image with controlled egress."""

    def __init__(
        self,
        workspace: Path,
        policy: DockerProvisioningPolicy,
        *,
        process_runner: ProcessRunner | None = None,
    ) -> None:
        self.workspace = workspace
        self.policy = policy
        self.process_runner = process_runner or AsyncioProcessRunner()

    async def provision(
        self,
        request: ProvisioningRequest,
        spec: EnvironmentSpec,
    ) -> ProvisioningReceipt:
        if request.expected_provisioner_identity != self.policy.provisioner_identity:
            raise ProvisioningExecutionError("request provisioner identity does not match policy")
        if spec.digest != request.environment_spec_digest:
            raise ProvisioningExecutionError("environment spec does not match authorized request")
        if spec.stack != "python":
            raise ProvisioningExecutionError("Docker provisioner v1 supports Python only")
        if any(not _valid_python_v1_step(step) for step in spec.steps):
            raise ProvisioningExecutionError(
                "Docker provisioner v1 accepts only detector-produced hash-locked Python steps"
            )

        source_digest = workspace_tree_digest(self.workspace)
        if source_digest != request.workspace_digest:
            raise ProvisioningExecutionError("workspace digest does not match authorized request")

        log_hasher = hashlib.sha256()
        started_at = datetime.now(timezone.utc)
        deadline = time.monotonic() + request.max_seconds

        async def run(
            argv: tuple[str, ...],
            *,
            requested_timeout: int,
            record: bool = True,
        ) -> ProcessResult:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                if record:
                    log_hasher.update(_digest_record(argv, None, timed_out=True))
                raise ProcessTimeout("overall provisioning deadline exceeded")
            timeout = max(1, min(requested_timeout, math.ceil(remaining)))
            try:
                result = await self.process_runner.run(argv, timeout_seconds=timeout)
            except ProcessTimeout:
                if record:
                    log_hasher.update(_digest_record(argv, None, timed_out=True))
                raise
            if record:
                log_hasher.update(_digest_record(argv, result, timed_out=False))
            return result

        image_check = await run(
            (self.policy.docker_executable, "image", "inspect", spec.base_image_ref),
            requested_timeout=30,
        )
        if image_check.returncode != 0:
            raise ProvisioningExecutionError("content-addressed base image is not available locally")

        network_name: str | None = None
        if any(step.network_required for step in spec.steps):
            if spec.network_policy_id is None:
                raise ProvisioningExecutionError("networked provisioning lacks an approved policy id")
            network_name = self.policy.resolve_network(spec.network_policy_id)
            network_check = await run(
                (
                    self.policy.docker_executable,
                    "network",
                    "inspect",
                    '--format={{index .Labels "factory.egress-controlled"}}|{{index .Labels "factory.egress-policy"}}',
                    network_name,
                ),
                requested_timeout=30,
            )
            expected = f"true|{spec.network_policy_id}"
            if network_check.returncode != 0 or network_check.stdout.decode(
                "utf-8", errors="replace"
            ).strip() != expected:
                raise ProvisioningExecutionError(
                    "Docker network is not attested for the requested controlled-egress policy"
                )

        # No dependencies means the already-content-addressed base image is the
        # environment. No container or commit is necessary.
        if not spec.steps:
            finished_at = datetime.now(timezone.utc)
            return ProvisioningReceipt(
                request_id=request.request_id,
                task_id=request.task_id,
                lease_id=request.lease_id,
                role_id=request.role_id,
                source_commit=request.source_commit,
                workspace_digest=request.workspace_digest,
                environment_spec_digest=request.environment_spec_digest,
                provisioner_identity=self.policy.provisioner_identity,
                result_image_ref=spec.base_image_ref,
                started_at=started_at,
                finished_at=finished_at,
                exit_code=0,
                timed_out=False,
                build_log_digest="sha256:" + log_hasher.hexdigest(),
            )

        with tempfile.TemporaryDirectory(prefix="factory-provision-") as temp_dir:
            copied_workspace = Path(temp_dir) / "workspace"
            _copy_workspace(self.workspace, copied_workspace)
            if workspace_tree_digest(copied_workspace) != request.workspace_digest:
                raise ProvisioningExecutionError(
                    "workspace changed while preparing provisioning copy"
                )

            container_name = f"factory-provision-{uuid.uuid4().hex[:12]}"
            container_id: str | None = None
            connected = False
            exit_code: int | None = None
            timed_out = False
            result_image_ref: str | None = None
            try:
                create = await run(
                    self._create_args(spec, container_name),
                    requested_timeout=60,
                )
                if create.returncode != 0:
                    raise ProvisioningExecutionError("Docker refused to create provisioning container")
                container_id = create.stdout.decode("utf-8", errors="replace").strip()
                if not CONTAINER_ID.fullmatch(container_id):
                    raise ProvisioningExecutionError("Docker returned an invalid provisioning container id")

                start = await run(
                    (self.policy.docker_executable, "start", container_id),
                    requested_timeout=30,
                )
                if start.returncode != 0:
                    raise ProvisioningExecutionError("Docker could not start provisioning container")

                mkdir = await run(
                    (
                        self.policy.docker_executable,
                        "exec",
                        "--user",
                        "0",
                        container_id,
                        "mkdir",
                        "-p",
                        "/workspace",
                    ),
                    requested_timeout=30,
                )
                if mkdir.returncode != 0:
                    raise ProvisioningExecutionError("could not prepare provisioning workspace")

                copy = await run(
                    (
                        self.policy.docker_executable,
                        "cp",
                        f"{copied_workspace}/.",
                        f"{container_id}:/workspace",
                    ),
                    requested_timeout=120,
                )
                if copy.returncode != 0:
                    raise ProvisioningExecutionError("could not copy workspace into provisioning container")

                for step in spec.steps:
                    assert network_name is not None
                    try:
                        connect = await run(
                            (
                                self.policy.docker_executable,
                                "network",
                                "connect",
                                network_name,
                                container_id,
                            ),
                            requested_timeout=30,
                        )
                        if connect.returncode != 0:
                            raise ProvisioningExecutionError(
                                "could not connect provisioning container to controlled egress"
                            )
                        connected = True

                        try:
                            step_result = await run(
                                (
                                    self.policy.docker_executable,
                                    "exec",
                                    "--user",
                                    "0",
                                    "--workdir",
                                    "/workspace",
                                    "--env",
                                    "HOME=/root",
                                    "--env",
                                    "CI=true",
                                    "--env",
                                    "PIP_DISABLE_PIP_VERSION_CHECK=1",
                                    container_id,
                                    *step.argv,
                                ),
                                requested_timeout=step.timeout_seconds,
                            )
                            exit_code = step_result.returncode
                        except (ProcessTimeout, ProcessOutputLimit):
                            timed_out = True
                            exit_code = None
                    finally:
                        if connected:
                            try:
                                disconnect = await self.process_runner.run(
                                    (
                                        self.policy.docker_executable,
                                        "network",
                                        "disconnect",
                                        network_name,
                                        container_id,
                                    ),
                                    timeout_seconds=30,
                                )
                                log_hasher.update(
                                    _digest_record(
                                        (
                                            self.policy.docker_executable,
                                            "network",
                                            "disconnect",
                                            network_name,
                                            container_id,
                                        ),
                                        disconnect,
                                        timed_out=False,
                                    )
                                )
                            except Exception:
                                # Cleanup will remove the container. We still
                                # fail closed if network isolation cannot be
                                # re-established before a commit.
                                connected = True
                            else:
                                connected = disconnect.returncode != 0

                    if timed_out or exit_code != 0:
                        break
                    if connected:
                        raise ProvisioningExecutionError(
                            "controlled-egress network could not be disconnected"
                        )

                if not timed_out and exit_code == 0:
                    remove_workspace = await run(
                        (
                            self.policy.docker_executable,
                            "exec",
                            "--user",
                            "0",
                            container_id,
                            "rm",
                            "-rf",
                            "/workspace",
                        ),
                        requested_timeout=30,
                    )
                    if remove_workspace.returncode != 0:
                        raise ProvisioningExecutionError(
                            "could not remove source workspace before environment commit"
                        )

                    commit = await run(
                        (self.policy.docker_executable, "commit", container_id),
                        requested_timeout=120,
                    )
                    candidate = commit.stdout.decode("utf-8", errors="replace").strip()
                    if commit.returncode != 0 or not IMAGE_ID.fullmatch(candidate):
                        raise ProvisioningExecutionError(
                            "Docker did not return a valid content-addressed image id"
                        )

                    inspect = await run(
                        (
                            self.policy.docker_executable,
                            "image",
                            "inspect",
                            "--format={{.Id}}",
                            candidate,
                        ),
                        requested_timeout=30,
                    )
                    confirmed = inspect.stdout.decode("utf-8", errors="replace").strip()
                    if inspect.returncode != 0 or confirmed != candidate:
                        raise ProvisioningExecutionError(
                            "committed environment image id could not be verified"
                        )
                    result_image_ref = candidate
            except ProcessTimeout:
                timed_out = True
                exit_code = None
            finally:
                if container_id is not None:
                    try:
                        cleanup_argv = (
                            self.policy.docker_executable,
                            "rm",
                            "-f",
                            container_id,
                        )
                        cleanup = await self.process_runner.run(
                            cleanup_argv,
                            timeout_seconds=30,
                        )
                        log_hasher.update(
                            _digest_record(cleanup_argv, cleanup, timed_out=False)
                        )
                    except Exception:
                        # Independent orphan-reaping is a separate runtime
                        # control. Cleanup failure never promotes a failed build.
                        pass

            finished_at = datetime.now(timezone.utc)
            if timed_out:
                return ProvisioningReceipt(
                    request_id=request.request_id,
                    task_id=request.task_id,
                    lease_id=request.lease_id,
                    role_id=request.role_id,
                    source_commit=request.source_commit,
                    workspace_digest=request.workspace_digest,
                    environment_spec_digest=request.environment_spec_digest,
                    provisioner_identity=self.policy.provisioner_identity,
                    result_image_ref=None,
                    started_at=started_at,
                    finished_at=finished_at,
                    exit_code=None,
                    timed_out=True,
                    build_log_digest="sha256:" + log_hasher.hexdigest(),
                )
            if exit_code != 0:
                return ProvisioningReceipt(
                    request_id=request.request_id,
                    task_id=request.task_id,
                    lease_id=request.lease_id,
                    role_id=request.role_id,
                    source_commit=request.source_commit,
                    workspace_digest=request.workspace_digest,
                    environment_spec_digest=request.environment_spec_digest,
                    provisioner_identity=self.policy.provisioner_identity,
                    result_image_ref=None,
                    started_at=started_at,
                    finished_at=finished_at,
                    exit_code=exit_code,
                    timed_out=False,
                    build_log_digest="sha256:" + log_hasher.hexdigest(),
                )
            if result_image_ref is None:
                raise ProvisioningExecutionError("successful provisioning produced no image")
            return ProvisioningReceipt(
                request_id=request.request_id,
                task_id=request.task_id,
                lease_id=request.lease_id,
                role_id=request.role_id,
                source_commit=request.source_commit,
                workspace_digest=request.workspace_digest,
                environment_spec_digest=request.environment_spec_digest,
                provisioner_identity=self.policy.provisioner_identity,
                result_image_ref=result_image_ref,
                started_at=started_at,
                finished_at=finished_at,
                exit_code=0,
                timed_out=False,
                build_log_digest="sha256:" + log_hasher.hexdigest(),
            )

    def _create_args(self, spec: EnvironmentSpec, container_name: str) -> tuple[str, ...]:
        return (
            self.policy.docker_executable,
            "create",
            "--pull=never",
            "--name",
            container_name,
            "--network=none",
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
            "--label",
            "factory.provisioning=true",
            "--entrypoint",
            "sleep",
            spec.base_image_ref,
            "infinity",
        )
