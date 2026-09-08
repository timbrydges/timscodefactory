import unittest
import app

class CaseTests(unittest.TestCase):
    def test_discount_reduces_price(self):
        self.assertEqual(app.apply_discount(100, 10), 90)

if __name__ == '__main__':
    unittest.main()
