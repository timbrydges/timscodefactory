import unittest
import app

class CaseTests(unittest.TestCase):
    def test_angle_brackets_and_ampersand(self):
        self.assertEqual(app.escape_untrusted("<b>&"), "&lt;b&gt;&amp;")

if __name__ == '__main__':
    unittest.main()
