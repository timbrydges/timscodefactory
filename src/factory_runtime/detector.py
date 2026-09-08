"""Deterministic repository-to-environment detection.

This module turns repository configuration into an EnvironmentSpec without
network access, image resolution, shell execution, or Factory state mutation.
It intentionally fails closed when stack/runtime selection is ambiguous or when
an approved digest-pinned base image is unavailable.
"""

from __future__ import annotations

import hashlib
import json
import re
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

import yaml

from .environment import EnvironmentSpec, ProvisionInput, ProvisionStep, ProvisioningContractError


PINNED_IMAGE = re.compile(r"^[^\s@]+@sha256:[0-9a-f]{64}$")
POLICY_KEY = re.compile(r"^[a-z0-9][a-z0-9._:-]{0,127}$")
PYTHON_LOWER_BOUND = re.compile(r"(?:>=|~=|==)\s*(\d+)\.(\d+)")
NODE_MAJOR = re.compile(r"(?:>=|\^|~|==)?\s*(\d+)(?:\.\d+)?")
DYNAMIC_GHA = re.compile(r"\$\{\{")


class EnvironmentDetectionError(ProvisioningContractError):
    """Raised when deterministic environment detection cannot proceed safely."""


@dataclass(frozen=True)
class BaseImagePolicy:
    """Approved immutable images available to the detector.

    Keys are stack names (``python``/``node``) or runtime-specific keys such as
    ``python:3.12`` and ``node:20``. Runtime-specific detection requires an exact
    policy key; the detector never silently falls back to another runtime.
    """

    images: tuple[tuple[str, str], ...]
    network_policy_id: str | None = None

    def __post_init__(self) -> None:
        keys = [key for key, _ in self.images]
        if len(set(keys)) != len(keys):
            raise EnvironmentDetectionError("base-image policy contains duplicate keys")
        for key, image in self.images:
            if not isinstance(key, str) or not POLICY_KEY.fullmatch(key):
                raise EnvironmentDetectionError(f"base-image policy key is invalid: {key!r}")
            if not isinstance(image, str) or not PINNED_IMAGE.fullmatch(image):
                raise EnvironmentDetectionError(
                    f"base-image policy image for {key!r} must be sha256-pinned"
                )
        if self.network_policy_id is not None:
            if not isinstance(self.network_policy_id, str) or not POLICY_KEY.fullmatch(
                self.network_policy_id
            ):
                raise EnvironmentDetectionError("network_policy_id is invalid")

    def resolve(self, stack: str, runtime_version: str | None) -> str:
        table = dict(self.images)
        key = f"{stack}:{runtime_version}" if runtime_version else stack
        image = table.get(key)
        if image is None:
            raise EnvironmentDetectionError(
                f"no approved digest-pinned base image for detector key {key!r}"
            )
        return image


@dataclass(frozen=True)
class DetectionResult:
    """Pure detection output; contains no authority and performs no provisioning."""

    spec: EnvironmentSpec
    stack: str
    runtime_version: str | None


_STACK_MARKERS: dict[str, tuple[str, ...]] = {
    "python": ("pyproject.toml", "setup.py", "setup.cfg", "requirements.txt", "requirements-ci.txt"),
    "node": ("package.json",),
    "java": ("pom.xml", "build.gradle", "build.gradle.kts"),
    "csharp": ("global.json",),
    "go": ("go.mod",),
    "rust": ("Cargo.toml",),
}


def _digest_file(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def _input(root: Path, path: Path) -> ProvisionInput:
    return ProvisionInput(path.relative_to(root).as_posix(), _digest_file(path))


def _existing_workflows(root: Path) -> tuple[Path, ...]:
    directory = root / ".github" / "workflows"
    if not directory.is_dir():
        return ()
    return tuple(sorted((*directory.glob("*.yml"), *directory.glob("*.yaml"))))


def _detect_root_stack(root: Path) -> str:
    hits: list[str] = []
    for stack, markers in _STACK_MARKERS.items():
        for marker in markers:
            if (root / marker).exists():
                hits.append(stack)
                break
    if not hits:
        raise EnvironmentDetectionError("no supported root stack could be detected")
    if len(hits) != 1:
        raise EnvironmentDetectionError(
            "ambiguous root stack: " + ", ".join(sorted(hits)) + "; monorepo fanout is required"
        )
    return hits[0]


def _load_workflow(path: Path) -> object:
    try:
        return yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise EnvironmentDetectionError(f"workflow {path.name!r} is unreadable: {exc}") from exc


def _walk(value: object) -> Iterable[object]:
    yield value
    if isinstance(value, dict):
        for child in value.values():
            yield from _walk(child)
    elif isinstance(value, list):
        for child in value:
            yield from _walk(child)


def _literal_version(value: object, *, kind: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise EnvironmentDetectionError(
            f"{kind} runtime versions in workflows must be quoted strings for deterministic parsing"
        )
    text = value.strip().lstrip("v")
    if not text:
        return None
    if DYNAMIC_GHA.search(text):
        return None
    if kind == "python":
        if not re.fullmatch(r"\d+\.\d+", text):
            raise EnvironmentDetectionError(f"unsupported literal Python version {value!r}")
        return text
    if kind == "node":
        match = re.fullmatch(r"(\d+)(?:\.\d+(?:\.\d+)?)?", text)
        if not match:
            raise EnvironmentDetectionError(f"unsupported literal Node version {value!r}")
        return match.group(1)
    raise EnvironmentDetectionError(f"unsupported runtime kind {kind!r}")


def _workflow_runtime_versions(workflows: tuple[Path, ...], *, kind: str) -> set[str]:
    versions: set[str] = set()
    setup_action = f"actions/setup-{kind}@"
    matrix_key = f"{kind}-version"
    for path in workflows:
        document = _load_workflow(path)
        for node in _walk(document):
            if not isinstance(node, dict):
                continue
            uses = node.get("uses")
            if isinstance(uses, str) and uses.startswith(setup_action):
                with_block = node.get("with")
                if isinstance(with_block, dict):
                    version = _literal_version(with_block.get(matrix_key), kind=kind)
                    if version:
                        versions.add(version)
            matrix = node.get("matrix")
            if isinstance(matrix, dict) and matrix_key in matrix:
                values = matrix[matrix_key]
                if not isinstance(values, list):
                    raise EnvironmentDetectionError(
                        f"workflow matrix {matrix_key!r} must be a literal list"
                    )
                for value in values:
                    version = _literal_version(value, kind=kind)
                    if version:
                        versions.add(version)
    return versions


def _single_workflow_version(workflows: tuple[Path, ...], *, kind: str) -> str | None:
    versions = _workflow_runtime_versions(workflows, kind=kind)
    if len(versions) > 1:
        raise EnvironmentDetectionError(
            f"multiple {kind} runtime versions detected ({', '.join(sorted(versions))}); "
            "environment fanout is required"
        )
    return next(iter(versions), None)


def _python_project(root: Path) -> dict:
    pyproject = root / "pyproject.toml"
    if not pyproject.exists():
        return {}
    try:
        with pyproject.open("rb") as handle:
            data = tomllib.load(handle)
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise EnvironmentDetectionError(f"pyproject.toml is unreadable: {exc}") from exc
    project = data.get("project") or {}
    if not isinstance(project, dict):
        raise EnvironmentDetectionError("pyproject.toml [project] must be a table")
    return project


def _python_declared_version(project: dict) -> str | None:
    requires = project.get("requires-python")
    if requires is None:
        return None
    if not isinstance(requires, str):
        raise EnvironmentDetectionError("project.requires-python must be a string")
    match = PYTHON_LOWER_BOUND.search(requires)
    if not match:
        raise EnvironmentDetectionError(
            f"cannot derive deterministic Python runtime from requires-python {requires!r}"
        )
    return f"{int(match.group(1))}.{int(match.group(2))}"


def _node_package(root: Path) -> dict:
    package = root / "package.json"
    try:
        data = json.loads(package.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise EnvironmentDetectionError(f"package.json is unreadable: {exc}") from exc
    if not isinstance(data, dict):
        raise EnvironmentDetectionError("package.json root must be an object")
    return data


def _node_declared_version(package: dict) -> str | None:
    engines = package.get("engines") or {}
    if not isinstance(engines, dict):
        raise EnvironmentDetectionError("package.json engines must be an object")
    value = engines.get("node")
    if value is None:
        return None
    if not isinstance(value, str):
        raise EnvironmentDetectionError("package.json engines.node must be a string")
    match = NODE_MAJOR.search(value)
    if not match:
        raise EnvironmentDetectionError(f"cannot derive Node runtime from engines.node {value!r}")
    return match.group(1)


def _logical_requirements(text: str) -> tuple[str, ...]:
    entries: list[str] = []
    current = ""
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if current:
            current += " " + line
        else:
            current = line
        if current.endswith("\\"):
            current = current[:-1].rstrip()
            continue
        entries.append(current)
        current = ""
    if current:
        entries.append(current)
    return tuple(entries)


def _hashed_requirements(path: Path) -> bool:
    entries = _logical_requirements(path.read_text(encoding="utf-8"))
    for entry in entries:
        if entry.startswith("--require-hashes"):
            continue
        if entry.startswith(("-r ", "--requirement ", "-c ", "--constraint ", "--index-url", "--extra-index-url")):
            return False
        if "==" not in entry or "--hash=sha256:" not in entry:
            return False
    return True


def _python_steps(root: Path, project: dict) -> tuple[ProvisionStep, ...]:
    for name in ("requirements-ci.txt", "requirements.txt"):
        path = root / name
        if path.exists():
            if not _hashed_requirements(path):
                raise EnvironmentDetectionError(
                    f"{name} is not fully hash-locked; refusing non-reproducible Python provisioning"
                )
            return (
                ProvisionStep(
                    step_id="install-python-dependencies",
                    argv=("python", "-m", "pip", "install", "--require-hashes", "-r", name),
                    timeout_seconds=900,
                    network_required=True,
                ),
            )

    if (root / "uv.lock").exists() or (root / "poetry.lock").exists():
        raise EnvironmentDetectionError(
            "Python lockfile detected but no approved lockfile-specific provisioning adapter exists yet"
        )

    dependencies = project.get("dependencies") or []
    optional = project.get("optional-dependencies") or {}
    if dependencies or optional:
        raise EnvironmentDetectionError(
            "Python dependencies are declared without a supported hash-locked requirements file"
        )
    return ()


def _node_steps(root: Path, package: dict) -> tuple[ProvisionStep, ...]:
    locks = [
        name
        for name in ("package-lock.json", "pnpm-lock.yaml", "yarn.lock")
        if (root / name).exists()
    ]
    if len(locks) > 1:
        raise EnvironmentDetectionError(
            "multiple Node lockfiles detected: " + ", ".join(locks)
        )
    dependencies = package.get("dependencies") or {}
    dev_dependencies = package.get("devDependencies") or {}
    if not locks:
        if dependencies or dev_dependencies:
            raise EnvironmentDetectionError("Node dependencies are declared without a lockfile")
        return ()
    lock = locks[0]
    if lock == "package-lock.json":
        argv = ("npm", "ci")
    elif lock == "pnpm-lock.yaml":
        argv = ("corepack", "pnpm", "install", "--frozen-lockfile")
    else:
        argv = ("corepack", "yarn", "install", "--immutable")
    return (
        ProvisionStep(
            step_id="install-node-dependencies",
            argv=argv,
            timeout_seconds=900,
            network_required=True,
        ),
    )


def _relevant_inputs(root: Path, stack: str, workflows: tuple[Path, ...]) -> tuple[ProvisionInput, ...]:
    if stack == "python":
        names = (
            "pyproject.toml",
            "requirements-ci.txt",
            "requirements.txt",
            "uv.lock",
            "poetry.lock",
        )
    elif stack == "node":
        names = ("package.json", "package-lock.json", "pnpm-lock.yaml", "yarn.lock")
    else:
        names = ()
    paths = [root / name for name in names if (root / name).exists()]
    paths.extend(workflows)
    return tuple(_input(root, path) for path in sorted(paths))


def detect_environment(root: Path | str, policy: BaseImagePolicy) -> DetectionResult:
    """Detect one deterministic root environment.

    The detector is intentionally conservative: ambiguous stacks, multi-runtime
    matrices, unsupported stacks, mutable images, malformed config, and
    non-reproducible dependency declarations are errors rather than guesses.
    """

    root = Path(root).resolve()
    if not root.is_dir():
        raise EnvironmentDetectionError("workspace root does not exist or is not a directory")
    stack = _detect_root_stack(root)
    if stack not in {"python", "node"}:
        raise EnvironmentDetectionError(
            f"detected stack {stack!r} is not supported by deterministic detector v1"
        )

    workflows = _existing_workflows(root)
    if stack == "python":
        project = _python_project(root)
        workflow_version = _single_workflow_version(workflows, kind="python")
        declared_version = _python_declared_version(project)
        runtime_version = workflow_version or declared_version
        if workflow_version and declared_version:
            wf_major_minor = tuple(map(int, workflow_version.split(".")))
            declared_major_minor = tuple(map(int, declared_version.split(".")))
            if wf_major_minor < declared_major_minor:
                raise EnvironmentDetectionError(
                    f"workflow Python {workflow_version} violates project lower bound {declared_version}"
                )
        steps = _python_steps(root, project)
    else:
        package = _node_package(root)
        workflow_version = _single_workflow_version(workflows, kind="node")
        declared_version = _node_declared_version(package)
        runtime_version = workflow_version or declared_version
        steps = _node_steps(root, package)

    image = policy.resolve(stack, runtime_version)
    requires_network = any(step.network_required for step in steps)
    if requires_network and policy.network_policy_id is None:
        raise EnvironmentDetectionError(
            "detected provisioning requires network access but no approved network policy is configured"
        )
    network_policy_id = policy.network_policy_id if requires_network else None
    spec = EnvironmentSpec(
        stack=stack,
        base_image_ref=image,
        inputs=_relevant_inputs(root, stack, workflows),
        steps=steps,
        network_policy_id=network_policy_id,
    )
    return DetectionResult(spec=spec, stack=stack, runtime_version=runtime_version)
