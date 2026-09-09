from __future__ import annotations

import unittest

from app import value


class BrokeredRepairCanaryTests(unittest.TestCase):
    def test_value_is_repaired(self):
        self.assertEqual(value(), 2)


if __name__ == "__main__":
    unittest.main()
