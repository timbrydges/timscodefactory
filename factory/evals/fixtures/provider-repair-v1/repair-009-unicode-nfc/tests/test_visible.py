import unittest
import app

class CaseTests(unittest.TestCase):
    def test_decomposed_unicode_normalized(self):
        self.assertEqual(app.canonical_name("e\u0301"), "é")

if __name__ == '__main__':
    unittest.main()
