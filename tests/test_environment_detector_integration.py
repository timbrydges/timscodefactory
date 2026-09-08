from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from factory_runtime.detector import BaseImagePolicy, detect_environment  # noqa: E402


class FactoryRepositoryEnvironmentDetectionTests(unittest.TestCase):
    def test_detector_understands_factory_repository(self):
        image = "python@sha256:" + "9" * 64
        result = detect_environment(
            ROOT,
            BaseImagePolicy(
                images=(("python:3.12", image),),
                network_policy_id="python-package-registry-v1",
            ),
        )
        self.assertEqual(result.stack, "python")
        self.assertEqual(result.runtime_version, "3.12")
        self.assertEqual(result.spec.base_image_ref, image)
        self.assertEqual(
            result.spec.steps[0].argv,
            ("python", "-m", "pip", "install", "--require-hashes", "-r", "requirements-ci.txt"),
        )
        input_paths = {item.path for item in result.spec.inputs}
        self.assertIn("pyproject.toml", input_paths)
        self.assertIn("requirements-ci.txt", input_paths)
        self.assertIn(".github/workflows/registry-ci.yml", input_paths)


if __name__ == "__main__":
    unittest.main()
