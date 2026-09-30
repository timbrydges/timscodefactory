import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))

from reconcile_live_inspector_review import classify


class InspectorReconcileTests(unittest.TestCase):
    def test_absent_reservation_is_pre_provider_failure(self):
        result = classify(budget_item=None, reviewer_versions=[], local_error={'x': 1})
        self.assertEqual(result['status'], 'NO_DURABLE_RESERVATION_FOUND')
        self.assertFalse(result['provider_call_may_have_occurred'])
        self.assertFalse(result['retry_permitted'])

    def test_reservation_always_blocks_retry(self):
        result = classify(budget_item={'PK': {}}, reviewer_versions=[], local_error=None)
        self.assertEqual(result['status'], 'ONE_CALL_RESERVATION_CONSUMED_OR_OUTCOME_UNCERTAIN')
        self.assertTrue(result['provider_call_may_have_occurred'])
        self.assertFalse(result['retry_permitted'])

    def test_receipt_reconciles_lost_client_result_without_retry(self):
        result = classify(
            budget_item={'PK': {}}, reviewer_versions=[{'version_id': 'v1'}],
            local_error={'errorMessage': 'client lost response'})
        self.assertEqual(result['status'], 'REVIEWER_RECEIPT_FOUND_AFTER_UNCERTAIN_CLIENT_RESULT')
        self.assertFalse(result['retry_permitted'])


if __name__ == '__main__':
    unittest.main()
