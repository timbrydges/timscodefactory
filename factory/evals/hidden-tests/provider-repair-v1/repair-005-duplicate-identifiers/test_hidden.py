import unittest
import app

class CaseTests(unittest.TestCase):
    def test_unique_ids_still_pass(self):
        self.assertTrue(app.validate_ids([{"id": "a"}, {"id": "b"}]))

    def test_late_duplicate_rejected(self):
        with self.assertRaises(ValueError):
            app.validate_ids([{"id": "a"}, {"id": "b"}, {"id": "a"}])

if __name__ == '__main__':
    unittest.main()
