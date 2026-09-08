from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from factory_runtime.detector import (  # noqa: E402
    BaseImagePolicy,
    EnvironmentDetectionError,
    detect_environment,
)


PY311 = "python@sha256:" + "1" * 64
PY312 = "python@sha256:" + "2" * 64
NODE20 = "node@sha256:" + "3" * 64
NETWORK = "package-registry-v1"


def policy(*entries: tuple[str, str], network: str | None = NETWORK) -> BaseImagePolicy:
    return BaseImagePolicy(images=tuple(entries), network_policy_id=network)


def write(root: Path, name: str, content: str) -> None:
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def hashed_requirements() -> str:
    return "jsonschema==4.26.0 --hash=sha256:" + "a" * 64 + "\n"


class EnvironmentDetectorTests(unittest.TestCase):
    def test_policy_rejects_mutable_image_tag(self):
        with self.assertRaises(EnvironmentDetectionError):
            policy(("python:3.12", "python:3.12-slim"))

    def test_policy_rejects_duplicate_keys(self):
        with self.assertRaises(EnvironmentDetectionError):
            policy(("python:3.12", PY312), ("python:3.12", PY312))

    def test_python_hash_locked_requirements_builds_shell_free_spec(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write(root, "pyproject.toml", '[project]\nname="x"\nrequires-python=">=3.12"\ndependencies=[]\n')
            write(root, "requirements-ci.txt", hashed_requirements())
            result = detect_environment(root, policy(("python:3.12", PY312)))
            self.assertEqual(result.stack, "python")
            self.assertEqual(result.runtime_version, "3.12")
            self.assertEqual(result.spec.base_image_ref, PY312)
            self.assertEqual(
                result.spec.steps[0].argv,
                ("python", "-m", "pip", "install", "--require-hashes", "-r", "requirements-ci.txt"),
            )
            self.assertEqual(result.spec.network_policy_id, NETWORK)

    def test_networked_provisioning_without_policy_is_denied(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write(root, "pyproject.toml", '[project]\nname="x"\nrequires-python=">=3.12"\ndependencies=[]\n')
            write(root, "requirements-ci.txt", hashed_requirements())
            with self.assertRaises(EnvironmentDetectionError):
                detect_environment(root, policy(("python:3.12", PY312), network=None))

    def test_workflow_runtime_overrides_project_lower_bound(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write(root, "pyproject.toml", '[project]\nname="x"\nrequires-python=">=3.11"\ndependencies=[]\n')
            write(
                root,
                ".github/workflows/ci.yml",
                'jobs:\n  test:\n    steps:\n      - uses: actions/setup-python@v5\n        with:\n          python-version: "3.12"\n',
            )
            result = detect_environment(root, policy(("python:3.12", PY312)))
            self.assertEqual(result.runtime_version, "3.12")
            paths = {item.path for item in result.spec.inputs}
            self.assertIn(".github/workflows/ci.yml", paths)

    def test_workflow_runtime_below_project_lower_bound_is_denied(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write(root, "pyproject.toml", '[project]\nname="x"\nrequires-python=">=3.12"\ndependencies=[]\n')
            write(
                root,
                ".github/workflows/ci.yml",
                'jobs:\n  test:\n    steps:\n      - uses: actions/setup-python@v5\n        with:\n          python-version: "3.11"\n',
            )
            with self.assertRaises(EnvironmentDetectionError):
                detect_environment(root, policy(("python:3.11", PY311)))

    def test_multi_runtime_matrix_requires_fanout(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write(root, "pyproject.toml", '[project]\nname="x"\nrequires-python=">=3.11"\ndependencies=[]\n')
            write(
                root,
                ".github/workflows/ci.yml",
                'jobs:\n  test:\n    strategy:\n      matrix:\n        python-version: ["3.11", "3.12"]\n    steps:\n      - uses: actions/setup-python@v5\n        with:\n          python-version: "${{ matrix.python-version }}"\n',
            )
            with self.assertRaises(EnvironmentDetectionError):
                detect_environment(
                    root,
                    policy(("python:3.11", PY311), ("python:3.12", PY312)),
                )

    def test_unquoted_numeric_workflow_runtime_is_denied(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write(root, "pyproject.toml", '[project]\nname="x"\nrequires-python=">=3.11"\ndependencies=[]\n')
            write(
                root,
                ".github/workflows/ci.yml",
                'jobs:\n  test:\n    steps:\n      - uses: actions/setup-python@v5\n        with:\n          python-version: 3.12\n',
            )
            with self.assertRaises(EnvironmentDetectionError):
                detect_environment(root, policy(("python:3.12", PY312)))

    def test_missing_exact_runtime_image_is_denied(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write(root, "pyproject.toml", '[project]\nname="x"\nrequires-python=">=3.12"\ndependencies=[]\n')
            with self.assertRaises(EnvironmentDetectionError):
                detect_environment(root, policy(("python", PY311)))

    def test_unhashed_python_requirements_are_denied(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write(root, "pyproject.toml", '[project]\nname="x"\nrequires-python=">=3.12"\ndependencies=[]\n')
            write(root, "requirements-ci.txt", "pytest==8.3.0\n")
            with self.assertRaises(EnvironmentDetectionError):
                detect_environment(root, policy(("python:3.12", PY312)))

    def test_python_dependencies_without_supported_lock_are_denied(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write(
                root,
                "pyproject.toml",
                '[project]\nname="x"\nrequires-python=">=3.12"\ndependencies=["requests==2.32.0"]\n',
            )
            with self.assertRaises(EnvironmentDetectionError):
                detect_environment(root, policy(("python:3.12", PY312)))

    def test_uv_lock_is_explicitly_denied_until_adapter_exists(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write(root, "pyproject.toml", '[project]\nname="x"\nrequires-python=">=3.12"\ndependencies=[]\n')
            write(root, "uv.lock", "version = 1\n")
            with self.assertRaises(EnvironmentDetectionError):
                detect_environment(root, policy(("python:3.12", PY312)))

    def test_node_package_lock_selects_npm_ci(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write(
                root,
                "package.json",
                '{"name":"x","engines":{"node":">=20"},"dependencies":{"left-pad":"1.3.0"}}',
            )
            write(root, "package-lock.json", '{"lockfileVersion":3}')
            result = detect_environment(root, policy(("node:20", NODE20)))
            self.assertEqual(result.stack, "node")
            self.assertEqual(result.runtime_version, "20")
            self.assertEqual(result.spec.steps[0].argv, ("npm", "ci"))

    def test_node_dependencies_without_lock_are_denied(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write(root, "package.json", '{"name":"x","dependencies":{"left-pad":"1.3.0"}}')
            with self.assertRaises(EnvironmentDetectionError):
                detect_environment(root, policy(("node", NODE20)))

    def test_multiple_node_lockfiles_are_denied(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write(root, "package.json", '{"name":"x"}')
            write(root, "package-lock.json", '{}')
            write(root, "yarn.lock", "# lock\n")
            with self.assertRaises(EnvironmentDetectionError):
                detect_environment(root, policy(("node", NODE20)))

    def test_ambiguous_root_stack_is_denied(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write(root, "pyproject.toml", '[project]\nname="x"\nrequires-python=">=3.12"\ndependencies=[]\n')
            write(root, "package.json", '{"name":"x"}')
            with self.assertRaises(EnvironmentDetectionError):
                detect_environment(
                    root,
                    policy(("python:3.12", PY312), ("node", NODE20)),
                )

    def test_unsupported_detected_stack_is_denied(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write(root, "go.mod", "module example.com/x\n")
            with self.assertRaises(EnvironmentDetectionError):
                detect_environment(root, policy(("go", "golang@sha256:" + "4" * 64)))

    def test_malformed_pyproject_is_denied(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write(root, "pyproject.toml", "[project\n")
            with self.assertRaises(EnvironmentDetectionError):
                detect_environment(root, policy(("python", PY312)))

    def test_malformed_workflow_is_denied(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write(root, "pyproject.toml", '[project]\nname="x"\nrequires-python=">=3.12"\ndependencies=[]\n')
            write(root, ".github/workflows/ci.yml", "jobs: [\n")
            with self.assertRaises(EnvironmentDetectionError):
                detect_environment(root, policy(("python:3.12", PY312)))

    def test_input_content_change_changes_environment_digest(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write(root, "pyproject.toml", '[project]\nname="x"\nrequires-python=">=3.12"\ndependencies=[]\n')
            first = detect_environment(root, policy(("python:3.12", PY312))).spec.digest
            write(root, "pyproject.toml", '[project]\nname="y"\nrequires-python=">=3.12"\ndependencies=[]\n')
            second = detect_environment(root, policy(("python:3.12", PY312))).spec.digest
            self.assertNotEqual(first, second)

    def test_missing_workspace_is_denied(self):
        with self.assertRaises(EnvironmentDetectionError):
            detect_environment("/definitely/not/a/factory/workspace", policy(("python", PY312)))


if __name__ == "__main__":
    unittest.main()
