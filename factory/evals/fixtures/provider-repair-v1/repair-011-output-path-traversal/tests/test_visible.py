import unittest
import app

class CaseTests(unittest.TestCase):
    def test_parent_traversal_rejected(self):
        with self.assertRaises(ValueError):
            app.validate_output_path("../report.md")

if __name__ == '__main__':
    unittest.main()
