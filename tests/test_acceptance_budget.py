import unittest
import sys
from datetime import datetime, timezone
from decimal import Decimal
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))

from factory_runtime.acceptance_budget import DynamoDBAcceptanceBudgetStore
from factory_state.model import StateError


class AtomicTable:
    def __init__(self):
        self.rows = {}
        self.calls = 0
        self.fail_after_commit = False
        self.fail_before_commit = False

    def transact_write_items(self, *, TransactItems):
        put, update = TransactItems
        item = put['Put']['Item']
        key = (item['PK']['S'], item['SK']['S'])
        if self.fail_before_commit:
            raise RuntimeError('outcome unknown before commit')
        if key in self.rows or self.calls >= 3:
            raise RuntimeError('transaction canceled')
        self.rows[key] = item
        self.calls += 1
        if self.fail_after_commit:
            raise RuntimeError('response lost after atomic commit')

    def get_item(self, *, TableName, Key, ConsistentRead):
        return {'Item': self.rows.get((Key['PK']['S'], Key['SK']['S']))}


class AcceptanceBudgetTests(unittest.TestCase):
    def setUp(self):
        self.table = AtomicTable()
        self.store = DynamoDBAcceptanceBudgetStore('tims-factory-acceptance-budget', self.table)
        self.options = {'activation_id': 'acceptance-1',
                        'maximum_cost_usd': Decimal('0.25'),
                        'maximum_provider_calls': 3,
                        'expires_at': datetime(2026, 9, 26, tzinfo=timezone.utc)}

    def reserve(self, dispatch):
        self.store.reserve(dispatch_id=dispatch, **self.options)

    def test_three_attempts_and_idempotent_replay(self):
        for dispatch in ('one', 'two', 'three'):
            self.reserve(dispatch)
        self.reserve('one')
        self.assertEqual(self.table.calls, 3)
        with self.assertRaisesRegex(StateError, 'exhausted'):
            self.reserve('four')

    def test_lost_response_reconciles_only_committed_identical_record(self):
        self.table.fail_after_commit = True
        self.reserve('one')
        self.reserve('one')
        self.assertEqual(self.table.calls, 1)
        self.options['expires_at'] = datetime(2026, 9, 27, tzinfo=timezone.utc)
        with self.assertRaisesRegex(StateError, 'conflicted'):
            self.reserve('one')

    def test_widened_authorization_fails_before_table_write(self):
        self.options['maximum_provider_calls'] = 4
        with self.assertRaisesRegex(StateError, 'owner authorization'):
            self.reserve('one')
        self.assertEqual(self.table.calls, 0)

    def test_unknown_outcome_never_grants_an_attempt(self):
        self.table.fail_before_commit = True
        with self.assertRaisesRegex(StateError, 'outcome unknown'):
            self.reserve('one')
        self.assertEqual(self.table.calls, 0)


if __name__ == '__main__':
    unittest.main()
