import unittest
import app

class CaseTests(unittest.TestCase):
    def test_duplicate_identifier_rejected(self):
        with self.assertRaises(ValueError):
            app.validate_ids([{"id": "a"}, {"id": "a"}])

if __name__ == '__main__':
    unittest.main()
