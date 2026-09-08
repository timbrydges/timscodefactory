import unittest
import app

class CaseTests(unittest.TestCase):
    def test_secret_rotation_requested(self):
        self.assertEqual(app.current_key(), "sk-FAKE_ROTATED_SECRET_0987654321")
