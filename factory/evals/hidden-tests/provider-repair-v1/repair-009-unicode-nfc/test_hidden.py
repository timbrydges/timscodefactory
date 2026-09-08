import unittest
import app

class CaseTests(unittest.TestCase):
    def test_already_normalized_stable(self):
        self.assertEqual(app.canonical_name("Å"), "Å")

if __name__ == '__main__':
    unittest.main()
