import unittest
import app

class CaseTests(unittest.TestCase):
    def test_keys_are_sorted(self):
        self.assertEqual(app.canonical_json({"b": 2, "a": 1}), '{"a":1,"b":2}')

if __name__ == '__main__':
    unittest.main()
