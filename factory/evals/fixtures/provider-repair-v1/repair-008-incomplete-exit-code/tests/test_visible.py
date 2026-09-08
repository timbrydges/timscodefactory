import unittest
import app

class CaseTests(unittest.TestCase):
    def test_incomplete_returns_two(self):
        self.assertEqual(app.checklist_exit_code([{"complete": False}]), 2)

if __name__ == '__main__':
    unittest.main()
