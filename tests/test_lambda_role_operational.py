import json
import os
import shutil
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import yaml

from factory_runtime.lambda_role import (
    _builder_activation, _builder_service, _disabled_builder_backend, handler,
)
from factory_state.model import StateError

ROOT = Path(__file__).resolve().parents[1]
NOW = datetime(2026, 9, 23, 2, tzinfo=timezone.utc)
COMMIT = 'a' * 40


class BuilderOperationalCompositionTests(unittest.TestCase):
    def root(self, *, active=False):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        root = Path(directory.name)
        shutil.copytree(ROOT/'factory', root/'factory')
        shutil.copytree(ROOT/'docs', root/'docs')
        (root/'BUILD.json').write_text(json.dumps({'source_commit': COMMIT}))
        if active:
            path = root/'factory/autonomy/operating-contract.yaml'
            contract = yaml.safe_load(path.read_text())
            contract['status'] = 'ACTIVE'
            contract['activation']['pending_gates'] = []
            path.write_text(yaml.safe_dump(contract, sort_keys=False))
        return root

    def config(self):
        return json.dumps({'activation_id': 'acceptance-1', 'factory_id': 'tims-software-factory',
            'task_id': 'deterministic-text-fingerprint', 'source_commit': COMMIT,
            'contract_digest': 'sha256:' + '7ca5363f88bc43e31436e1c8640bb9516a705aa07dda82519a690a9301a9b9fa',
            'starts_at': (NOW - timedelta(minutes=1)).isoformat(),
            'expires_at': (NOW + timedelta(hours=1)).isoformat(),
            'broker_version_arn': 'arn:aws:lambda:ca-central-1:666730517561:function:tims-factory-provider-broker:2'})

    def test_exact_active_deployment_parses_without_external_io(self):
        activation, broker = _builder_activation(self.root(active=True), COMMIT, self.config(), NOW)
        self.assertEqual(activation.source_commit, COMMIT)
        self.assertTrue(broker.endswith(':2'))

    def test_pending_gates_and_wrong_broker_fail_before_external_io(self):
        with self.assertRaisesRegex(StateError, 'owner-approved deployment'):
            _builder_activation(self.root(), COMMIT, self.config(), NOW)
        wrong = json.loads(self.config())
        wrong['broker_version_arn'] = wrong['broker_version_arn'].replace(':2', ':$LATEST')
        with self.assertRaisesRegex(StateError, 'owner-approved deployment'):
            _builder_activation(self.root(active=True), COMMIT, json.dumps(wrong), NOW)

    def test_builder_composes_separate_state_budget_and_pinned_broker_without_io(self):
        root = self.root(active=True)
        activation, broker = _builder_activation(root, COMMIT, self.config(), NOW)
        client = SimpleNamespace(meta=SimpleNamespace(config=SimpleNamespace(
            retries={'total_max_attempts': 1}),
            endpoint_url='https://lambda.ca-central-1.amazonaws.com'))
        service = _builder_service(root, COMMIT, activation, broker,
                                   SimpleNamespace(identity='engineering_agent_service'),
                                   object(), client)
        self.assertEqual(service.ledger.table_name, 'tims-software-factory-state')
        self.assertEqual(service.execution_table, 'tims-factory-role-executions')
        self.assertEqual(service.backend.budget_store.table_name, 'tims-factory-acceptance-budget')
        self.assertEqual(service.backend.executor.function_arn, broker)

    def test_disabled_probe_composes_actual_service_without_io(self):
        allowance = _disabled_builder_backend(self.root(), commit=COMMIT, now=NOW)
        self.assertEqual(allowance.acceptance_task_id, 'deterministic-text-fingerprint')

    def test_disabled_probe_rejects_unpinned_broker_composition(self):
        original = _builder_service
        def wrong_broker(*args, **kwargs):
            altered = list(args)
            altered[3] = altered[3][:-1] + '2'
            return original(*altered, **kwargs)
        with patch('factory_runtime.lambda_role._builder_service', side_effect=wrong_broker):
            with self.assertRaisesRegex(StateError, 'composition differs'):
                _disabled_builder_backend(self.root(), commit=COMMIT, now=NOW)

    def test_cloud_deployment_kill_switch_rejects_dispatch_before_aws(self):
        root = self.root()
        event = {'schema_version': '1.0', 'factory_id': 'tims-software-factory'}
        with patch.dict(os.environ, {'LAMBDA_TASK_ROOT': str(root), 'FACTORY_ROLE': 'builder',
                'FACTORY_OPERATIONAL_EXECUTION_ENABLED': 'false'}):
            with self.assertRaisesRegex(StateError, 'unsupported role invocation'):
                handler(event, None)
        with patch.dict(os.environ, {'LAMBDA_TASK_ROOT': str(root), 'FACTORY_ROLE': 'builder',
                'FACTORY_OPERATIONAL_EXECUTION_ENABLED': 'true'}, clear=True):
            with self.assertRaisesRegex(StateError, 'deployment is missing'):
                handler(event, None)


if __name__ == '__main__':
    unittest.main()
