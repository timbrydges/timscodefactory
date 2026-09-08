import pathlib
import unittest

class CaseTests(unittest.TestCase):
    def test_workflow_is_read_only(self):
        text = pathlib.Path(".github/workflows/ci.yml").read_text()
        self.assertIn("contents: read", text)
