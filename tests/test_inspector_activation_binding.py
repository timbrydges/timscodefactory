import copy
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / 'src'), str(ROOT / 'scripts')]
from verify_inspector_activation_binding import (
    INSPECTOR_ACTIVATION_ID, INSPECTOR_AUTHORIZATION_ID, expected_reservation, verify, verify_policy)


class InspectorActivationBindingTests(unittest.TestCase):
    def test_checked_in_iam_owner_record_and_runtime_are_same_activation(self):
        result = verify()
        self.assertEqual(result['activation_id'], INSPECTOR_ACTIVATION_ID)
        self.assertEqual(result['model_calls'], 0)

    def test_prior_activation_wildcard_missing_or_duplicate_budget_permission_denied(self):
        expected = expected_reservation()
        for leading in (['INSPECTOR#inspector-fallback-2026-10-01-006'], ['INSPECTOR#*'],
                        ['INSPECTOR#' + INSPECTOR_ACTIVATION_ID, 'INSPECTOR#another']):
            statement = copy.deepcopy(expected)
            statement['Condition']['ForAllValues:StringEquals']['dynamodb:LeadingKeys'] = leading
            with self.subTest(leading=leading), self.assertRaisesRegex(RuntimeError, 'no invocation allowed'):
                verify_policy({'Statement': [statement]})
        for statements in ([], [expected, expected]):
            with self.assertRaises(RuntimeError):
                verify_policy({'Statement': statements})

    def test_wrong_owner_record_activation_denied_before_deployment(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / 'factory/evidence'; target.mkdir(parents=True)
            relative = f'factory/evidence/{INSPECTOR_AUTHORIZATION_ID}.json'
            record = json.loads((ROOT / relative).read_text())
            record['activation_id'] = 'another'
            (root / relative).write_text(json.dumps(record))
            with self.assertRaisesRegex(RuntimeError, 'authorization evidence differs'):
                verify(root)


if __name__ == '__main__':
    unittest.main()
