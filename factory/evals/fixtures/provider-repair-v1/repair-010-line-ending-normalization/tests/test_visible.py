import unittest
import app

class CaseTests(unittest.TestCase):
    def test_lone_carriage_return_normalized(self):
        self.assertEqual(app.normalize_lines("a\rb"), "a\nb")

if __name__ == '__main__':
    unittest.main()
