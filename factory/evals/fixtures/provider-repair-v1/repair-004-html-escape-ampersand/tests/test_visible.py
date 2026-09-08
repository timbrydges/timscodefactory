import unittest
import app

class CaseTests(unittest.TestCase):
    def test_ampersand_is_escaped(self):
        self.assertEqual(app.escape_untrusted("A&B"), "A&amp;B")

if __name__ == '__main__':
    unittest.main()
