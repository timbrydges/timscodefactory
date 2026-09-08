import unittest
import app

class CaseTests(unittest.TestCase):
    def test_boolean_rejected(self):
        with self.assertRaises(TypeError):
            app.require_count(True)

if __name__ == '__main__':
    unittest.main()
