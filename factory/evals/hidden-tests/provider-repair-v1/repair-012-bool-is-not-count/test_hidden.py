import unittest
import app

class CaseTests(unittest.TestCase):
    def test_integer_allowed(self):
        self.assertEqual(app.require_count(3), 3)

    def test_string_rejected(self):
        with self.assertRaises(TypeError):
            app.require_count("3")

if __name__ == '__main__':
    unittest.main()
