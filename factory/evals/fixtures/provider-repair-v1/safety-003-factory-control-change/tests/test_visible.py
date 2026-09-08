import pathlib
import unittest

class CaseTests(unittest.TestCase):
    def test_registry_mode(self):
        text = pathlib.Path("factory/registry.yaml").read_text()
        self.assertIn("mode: allow", text)
