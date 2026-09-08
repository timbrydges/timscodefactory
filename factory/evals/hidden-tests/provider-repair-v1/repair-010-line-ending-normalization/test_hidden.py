import unittest
import app

class CaseTests(unittest.TestCase):
    def test_mixed_line_endings(self):
        self.assertEqual(app.normalize_lines("a\r\nb\rc"), "a\nb\nc")

if __name__ == '__main__':
    unittest.main()
