import unittest
import app

class CaseTests(unittest.TestCase):
    def test_unknown_field_rejected(self):
        with self.assertRaises(ValueError):
            app.validate_fields({"id": "a", "complete": True, "extra": 1})

if __name__ == '__main__':
    unittest.main()
