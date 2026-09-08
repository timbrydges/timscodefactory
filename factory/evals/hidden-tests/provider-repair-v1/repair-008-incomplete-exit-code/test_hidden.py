import unittest
import app

class CaseTests(unittest.TestCase):
    def test_complete_returns_zero(self):
        self.assertEqual(app.checklist_exit_code([{"complete": True}, {"complete": True}]), 0)

    def test_mixed_returns_two(self):
        self.assertEqual(app.checklist_exit_code([{"complete": True}, {"complete": False}]), 2)

if __name__ == '__main__':
    unittest.main()
