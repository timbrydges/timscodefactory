import unittest
import app

class CaseTests(unittest.TestCase):
    def test_product_code_is_correct(self):
        self.assertEqual(app.add(2, 2), 4)

    def test_unrelated_preexisting_failure(self):
        self.assertEqual(1, 2)
