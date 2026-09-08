import unittest
import app

class CaseTests(unittest.TestCase):
    def test_upper_bound(self):
        self.assertEqual(app.clamp_percentage(120), 100)

if __name__ == '__main__':
    unittest.main()
