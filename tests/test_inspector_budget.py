import json
import sys
import unittest
from datetime import datetime, timezone, timedelta
from decimal import Decimal
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))

from factory_runtime.inspector_budget import InspectorBudgetStore, _price
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
        self.quote = json.loads((ROOT/'factory/evidence/acceptance-inspector-pricing-2026-09-29.json').read_text())
        self.now = datetime(2026, 9, 29, 11, 0, tzinfo=timezone.utc)
        self.table = ConditionalTable()
        self.budget = InspectorBudgetStore('tims-factory-acceptance-budget', self.table)
        self.args = dict(activation_id='acceptance-001', plan_digest='sha256:' + 'a'*64,
            request_bytes=b'exact request', input_tokens=42020,
            maximum_output_tokens=4096, quote=self.quote, now=self.now)

    def test_exact_global_quote_and_one_reservation(self):
        self.assertEqual(_price(self.quote, now=self.now, input_tokens=42020,
                                maximum_output_tokens=4096), Decimal('0.125'))
        result = self.budget.reserve(**self.args)
        self.assertEqual(result['status'], 'RESERVED_NOT_INVOKED')
        self.assertEqual(result['provider_calls_remaining'], 0)
        self.assertEqual(self.table.items[('INSPECTOR#acceptance-001', 'BUDGET')]
                         ['maximum_cost_microusd']['N'], '250000')
        with self.assertRaises(StateError):
            self.budget.reserve(**self.args)
        with self.assertRaises(StateError):
            self.budget.reserve(**{**self.args, 'plan_digest': 'sha256:' + 'b'*64})

    def test_geo_quote_stale_quote_and_oversized_request_fail_closed(self):
        for change in ({'inference_scope': 'Geo and In-region Cross-region Inference'},
                       {'input_usd_per_million_tokens': '2.20'},
                       {'model_id': 'global.anthropic.claude-sonnet-5'},
                       {'maximum_provider_calls': 2}):
            with self.subTest(change=change), self.assertRaises(StateError):
                self.budget.reserve(**{**self.args, 'quote': {**self.quote, **change}})
        with self.assertRaises(StateError):
            self.budget.reserve(**{**self.args, 'now': self.now + timedelta(days=2)})
        with self.assertRaises(StateError):
            self.budget.reserve(**{**self.args, 'request_bytes': b'x'*42021})
        with self.assertRaises(StateError):
            self.budget.reserve(**{**self.args, 'input_tokens': 42021})
        self.assertFalse(self.table.items)


if __name__ == '__main__':
    unittest.main()
