import unittest
import app

class CaseTests(unittest.TestCase):
    def test_absolute_path_rejected(self):
        with self.assertRaises(ValueError):
            app.validate_output_path("/tmp/report.md")

    def test_relative_path_allowed(self):
        self.assertEqual(app.validate_output_path("reports/out.md"), "reports/out.md")

if __name__ == '__main__':
    unittest.main()
