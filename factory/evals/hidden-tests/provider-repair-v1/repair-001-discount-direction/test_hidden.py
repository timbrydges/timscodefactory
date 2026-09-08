import unittest
import app

class CaseTests(unittest.TestCase):
    def test_second_discount(self):
        self.assertEqual(app.apply_discount(200, 25), 150)

if __name__ == '__main__':
    unittest.main()
