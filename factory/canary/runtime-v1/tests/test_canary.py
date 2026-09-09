from __future__ import annotations

import os
import unittest
from pathlib import Path

from app import add


class RuntimeCanaryTests(unittest.TestCase):
    def test_application_executes(self):
        self.assertEqual(add(20, 22), 42)

    def test_verification_container_has_no_external_network_interface(self):
        interfaces = sorted(path.name for path in Path("/sys/class/net").iterdir())
        self.assertEqual(interfaces, ["lo"])

    def test_verification_container_is_non_root_without_effective_capabilities(self):
        self.assertNotEqual(os.geteuid(), 0)
        status = Path("/proc/self/status").read_text(encoding="utf-8")
        fields = {
            line.split(":", 1)[0]: line.split(":", 1)[1].strip()
            for line in status.splitlines()
            if ":" in line
        }
        self.assertEqual(fields.get("NoNewPrivs"), "1")
        self.assertEqual(fields.get("CapEff"), "0000000000000000")

    def test_verification_root_filesystem_is_read_only(self):
        mount_line = next(
            line for line in Path("/proc/mounts").read_text(encoding="utf-8").splitlines()
            if line.split()[1] == "/"
        )
        mount_options = set(mount_line.split()[3].split(","))
        self.assertIn("ro", mount_options)

    def test_runtime_environment_is_bounded(self):
        self.assertEqual(os.environ.get("HOME"), "/tmp")
        self.assertEqual(os.environ.get("CI"), "true")


if __name__ == "__main__":
    unittest.main()
