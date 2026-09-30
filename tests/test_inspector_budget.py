import json
import sys
import unittest
from datetime import datetime, timezone, timedelta
from decimal import Decimal
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))

from factory_runtime.inspector_budget import (
    InspectorBudgetStore, MAX_REQUEST_BYTES, RESERVED_INPUT_TOKENS, _price)
from factory_state.model import StateError


class ConditionalTable:
    def __init__(self):
        self.items = {}

    def put_item(self, *, TableName, Item, ConditionExpression):
        assert ConditionExpression == 'attribute_not_exists(PK) AND attribute_not_exists(SK)'
        key = (Item['PK']['S'], Item['SK']['S'])
        if key in self.items:
            raise RuntimeError('conditional write failed')
        self.items[key] = Item


class InspectorBudgetTests(unittest.TestCase):
    def setUp(self):
        self.policy = json.loads((ROOT/'factory/evidence/acceptance-inspector-budget-policy-2026-09-29.json').read_text())
        self.now = datetime(2026, 9, 29, 11, 0, tzinfo=timezone.utc)
        self.table = ConditionalTable()
        self.budget = InspectorBudgetStore('tims-factory-acceptance-budget', self.table)
        self.args = dict(activation_id='acceptance-001', plan_digest='sha256:' + 'a'*64,
            request_bytes=b'exact request', policy=self.policy, now=self.now)

    def test_fixed_conservative_reservation_is_below_call_cap(self):
        self.assertEqual(_price(self.policy, now=self.now), Decimal('0.24096'))
        result = self.budget.reserve(**self.args)
        self.assertEqual(result['status'], 'RESERVED_NOT_INVOKED')
        self.assertEqual(result['provider_calls_remaining'], 0)
        self.assertEqual(result['reserved_input_tokens'], RESERVED_INPUT_TOKENS)
        item = self.table.items[('INSPECTOR#acceptance-001', 'BUDGET')]
        self.assertEqual(item['maximum_cost_microusd']['N'], '250000')
        self.assertEqual(item['reserved_cost_microusd']['N'], '240960')
        self.assertEqual(item['reserved_input_tokens']['N'], '100000')
        with self.assertRaises(StateError):
            self.budget.reserve(**self.args)
        with self.assertRaises(StateError):
            self.budget.reserve(**{**self.args, 'plan_digest': 'sha256:' + 'b'*64})

    def test_stale_or_drifted_policy_and_oversized_request_fail_closed(self):
        for change in ({'input_usd_per_million_tokens': '2.20'},
                       {'model_id': 'global.anthropic.claude-sonnet-5'},
                       {'maximum_provider_calls': 2},
                       {'reserved_input_tokens': 99999},
                       {'conservative_maximum_cost_usd': '0.25'}):
            with self.subTest(change=change), self.assertRaises(StateError):
                self.budget.reserve(**{**self.args, 'policy': {**self.policy, **change}})
        with self.assertRaises(StateError):
            self.budget.reserve(**{**self.args, 'now': self.now + timedelta(days=2)})
        with self.assertRaises(StateError):
            self.budget.reserve(**{**self.args, 'request_bytes': b'x'*(MAX_REQUEST_BYTES + 1)})
        self.assertFalse(self.table.items)


if __name__ == '__main__':
    unittest.main()
