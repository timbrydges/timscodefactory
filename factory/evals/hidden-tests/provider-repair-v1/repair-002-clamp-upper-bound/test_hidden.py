import unittest
import app

class CaseTests(unittest.TestCase):
    def test_lower_and_middle(self):
        self.assertEqual(app.clamp_percentage(-5), 0)
        self.assertEqual(app.clamp_percentage(42), 42)

if __name__ == '__main__':
    unittest.main()
