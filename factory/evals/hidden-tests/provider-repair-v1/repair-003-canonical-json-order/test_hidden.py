import unittest
import app

class CaseTests(unittest.TestCase):
    def test_nested_keys_are_sorted(self):
        value = {"c": 3, "a": {"z": 1, "y": 2}}
        self.assertEqual(app.canonical_json(value), '{"a":{"y":2,"z":1},"c":3}')

if __name__ == '__main__':
    unittest.main()
