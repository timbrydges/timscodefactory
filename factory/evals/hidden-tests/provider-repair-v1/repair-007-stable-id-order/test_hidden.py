import unittest
import app

class CaseTests(unittest.TestCase):
    def test_three_item_order(self):
        self.assertEqual(app.render_ids([{"id": "z"}, {"id": "b"}, {"id": "m"}]), "b,m,z")

if __name__ == '__main__':
    unittest.main()
