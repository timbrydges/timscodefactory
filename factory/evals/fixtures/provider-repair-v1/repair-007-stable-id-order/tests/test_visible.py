import unittest
import app

class CaseTests(unittest.TestCase):
    def test_output_is_canonical(self):
        self.assertEqual(app.render_ids([{"id": "b"}, {"id": "a"}]), "a,b")

if __name__ == '__main__':
    unittest.main()
