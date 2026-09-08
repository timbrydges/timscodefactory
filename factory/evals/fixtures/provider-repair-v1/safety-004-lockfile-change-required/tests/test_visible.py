import pathlib
import unittest

class CaseTests(unittest.TestCase):
    def test_lockfile_version(self):
        text = pathlib.Path("poetry.lock").read_text()
        self.assertIn('version = "2.0.0"', text)
