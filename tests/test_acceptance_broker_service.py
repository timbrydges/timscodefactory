import base64
import hashlib
import shutil
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))

from factory_runtime.acceptance_broker_service import AcceptanceBrokerService
from factory_runtime.autonomy import AutonomyActivation
from factory_state.model import StateError

NOW = datetime(2026, 9, 23, 2, tzinfo=timezone.utc)


class Budget:
    def __init__(self):
        self.reserved = set()

    def assert_reserved(self, **binding):
        if binding['dispatch_id'] not in self.reserved:
            raise StateError('reservation missing')


class Claims:
    def __init__(self):
        self.records = {}

    def begin(self, *, activation_id, dispatch_id, event_digest):
        key = (activation_id, dispatch_id)
        prior = self.records.get(key)
        if prior:
            if prior[0] != event_digest or prior[1] is None:
                raise StateError('unknown broker outcome')
            return prior[1]
        self.records[key] = (event_digest, None)
        return None

    def complete(self, *, activation_id, dispatch_id, event_digest, response):
        self.records[(activation_id, dispatch_id)] = (event_digest, response)


class Provider:
    def __init__(self):
        self.calls = 0
        self.fail = False

    def generate(self, **kwargs):
        self.calls += 1
        if self.fail:
            raise RuntimeError('unknown provider outcome')
        return b'bounded output', Decimal('0.12')


class AcceptanceBrokerServiceTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        shutil.copytree(ROOT / 'factory', self.root / 'factory')
        shutil.copytree(ROOT / 'docs', self.root / 'docs')
        path = self.root / 'factory/autonomy/operating-contract.yaml'
        contract = yaml.safe_load(path.read_text())
        contract['status'] = 'ACTIVE'
        contract['activation']['pending_gates'] = []
        path.write_text(yaml.safe_dump(contract, sort_keys=False))
        self.activation = AutonomyActivation('acceptance-1', 'factory',
            'deterministic-text-fingerprint', 'a' * 40, 'sha256:' + 'b' * 64,
            NOW - timedelta(minutes=1), NOW + timedelta(hours=1))
        self.budget, self.claims, self.provider = Budget(), Claims(), Provider()
        self.service = AcceptanceBrokerService(self.root, self.activation, self.budget,
                                                self.claims, self.provider, lambda: NOW, True)
        raw = b'approved input'
        self.event = {'schema_version': '1.0', 'kind': 'acceptance_provider_call',
            'activation_id': 'acceptance-1', 'dispatch_id': 'dispatch-1',
            'source_commit': 'a' * 40, 'contract_digest': 'sha256:' + 'b' * 64,
            'task_id': 'deterministic-text-fingerprint',
            'target_alias': 'coding_primary_sol_live', 'model_id': 'gpt-5.6-sol',
            'maximum_cost_usd': '0.25', 'input_digest': 'sha256:' + hashlib.sha256(raw).hexdigest(),
            'input_base64': base64.b64encode(raw).decode()}

    def test_disabled_and_unreserved_fail_before_provider(self):
        self.service.enabled = False
        with self.assertRaisesRegex(StateError, 'disabled'):
            self.service.handle(self.event)
        self.service.enabled = True
        with self.assertRaisesRegex(StateError, 'reservation missing'):
            self.service.handle(self.event)
        self.assertEqual(self.provider.calls, 0)

    def test_one_exact_call_and_replay_return_same_result(self):
        self.budget.reserved.add('dispatch-1')
        first = self.service.handle(self.event)
        self.assertEqual(self.service.handle(self.event), first)
        self.assertEqual(self.provider.calls, 1)
        self.assertEqual(first['cost_usd'], '0.12')

    def test_unknown_provider_outcome_is_never_retried(self):
        self.budget.reserved.add('dispatch-1')
        self.provider.fail = True
        with self.assertRaisesRegex(RuntimeError, 'unknown provider'):
            self.service.handle(self.event)
        with self.assertRaisesRegex(StateError, 'unknown broker'):
            self.service.handle(self.event)
        self.assertEqual(self.provider.calls, 1)

    def test_changed_binding_or_expired_price_fails_before_provider(self):
        self.budget.reserved.add('dispatch-1')
        for change in ({'model_id': 'other'}, {'input_digest': 'sha256:' + '0' * 64}):
            with self.subTest(change=change):
                with self.assertRaises(StateError):
                    self.service.handle({**self.event, **change})
        self.service.clock = lambda: datetime(2026, 9, 24, 1, tzinfo=timezone.utc)
        with self.assertRaisesRegex(StateError, 'pricing'):
            self.service.handle(self.event)
        self.assertEqual(self.provider.calls, 0)


if __name__ == '__main__':
    unittest.main()
