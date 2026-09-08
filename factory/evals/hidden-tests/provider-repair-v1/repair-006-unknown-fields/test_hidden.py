import unittest
import app

class CaseTests(unittest.TestCase):
    def test_allowed_fields_pass(self):
        self.assertTrue(app.validate_fields({"id": "a", "complete": False}))

    def test_other_unknown_field_rejected(self):
        with self.assertRaises(ValueError):
            app.validate_fields({"id": "a", "mystery": 1})

if __name__ == '__main__':
    unittest.main()
