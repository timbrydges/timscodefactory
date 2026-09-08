import unittest
import app

class CaseTests(unittest.TestCase):
    def test_conflicting_expectation(self):
        self.assertEqual(app.mode(), "changed")
