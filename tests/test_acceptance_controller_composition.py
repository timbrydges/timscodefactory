import json
import shutil
import tempfile
import unittest
from datetime import datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import yaml

from factory_runtime.autonomy_controller_lambda import (
    _controller_activation, _controller_service,
)
from factory_state.model import StateError

ROOT = Path(__file__).resolve().parents[1]
CONTRACT = yaml.safe_load((ROOT/'factory/autonomy/operating-contract.yaml').read_text())
NOW = datetime.fromisoformat(CONTRACT['pricing_reference']['observed_at'].replace('Z', '+00:00')) + timedelta(hours=1)
COMMIT = 'a' * 40
BUILDER = 'arn:aws:lambda:ca-central-1:666730517561:function:tims-factory-builder:8'


class NoIO:
    def __init__(self, endpoint):
        self.meta = SimpleNamespace(config=SimpleNamespace(retries={'total_max_attempts': 1}),
                                    endpoint_url=endpoint)

    def __getattr__(self, name):
        raise AssertionError(f'controller composition performed {name} IO')


class ControllerCompositionTests(unittest.TestCase):
    def root(self, *, active=False):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        root = Path(directory.name)
        shutil.copytree(ROOT/'factory', root/'factory')
        shutil.copytree(ROOT/'docs', root/'docs')
        if active:
            path = root/'factory/autonomy/operating-contract.yaml'
            contract = yaml.safe_load(path.read_text())
            contract['status'] = 'ACTIVE'
            contract['activation']['pending_gates'] = []
            path.write_text(yaml.safe_dump(contract, sort_keys=False))
        return root

    def config(self, **changes):
        value = {'activation_id': 'acceptance-1', 'factory_id': 'tims-software-factory',
            'task_id': 'deterministic-text-fingerprint', 'source_commit': COMMIT,
            'contract_digest': 'sha256:' + CONTRACT['acceptance_target']['contract_sha256'],
            'starts_at': (NOW - timedelta(minutes=1)).isoformat(),
            'expires_at': (NOW + timedelta(hours=1)).isoformat(),
            'builder_version_arn': BUILDER,
            'job_versions': {'IMPLEMENTATION': {'version_id': 'version-1',
                'sha256': 'sha256:' + 'b' * 64}}}
        return json.dumps({**value, **changes})

    def test_pending_contract_rejects_live_composition_before_io(self):
        with self.assertRaisesRegex(StateError, 'owner allowance'):
            _controller_activation(self.root(), COMMIT, self.config(), NOW)

    def test_exact_active_composition_is_credential_free_and_model_free(self):
        root = self.root(active=True)
        activation, builder_arn, versions = _controller_activation(
            root, COMMIT, self.config(), NOW)
        database = NoIO('https://dynamodb.ca-central-1.amazonaws.com')
        s3 = NoIO('https://s3.ca-central-1.amazonaws.com')
        lambda_api = NoIO('https://lambda.ca-central-1.amazonaws.com')
        service = _controller_service(root, COMMIT, activation, builder_arn, versions,
            database, s3, lambda_api, clock=lambda: NOW)
        self.assertEqual(service.scheduler.jobs.versions, versions)
        self.assertEqual(service.scheduler.cycle.worker.executors[
            'engineering_agent'].function_arn, BUILDER)
        self.assertEqual(service.scheduler.cycle.worker.executors[
            'engineering_agent'].guard.budget_store.table_name,
            'tims-factory-acceptance-budget')
        with self.assertRaisesRegex(StateError, 'cannot execute a provider'):
            service.scheduler.cycle.worker.executors[
                'engineering_agent'].guard.executor.execute()

    def test_wrong_role_unpinned_job_and_stale_quote_reject_before_io(self):
        root = self.root(active=True)
        for changed in (
            {'builder_version_arn': BUILDER.replace('builder', 'inspector')},
            {'builder_version_arn': BUILDER.replace(':8', ':$LATEST')},
            {'job_versions': {'IMPLEMENTATION': {'version_id': 'null',
                'sha256': 'sha256:' + 'b' * 64}}},
            {'job_versions': {'INSPECTION': {'version_id': 'version-1',
                'sha256': 'sha256:' + 'b' * 64}}},
        ):
            with self.subTest(changed=changed), self.assertRaises(StateError):
                _controller_activation(root, COMMIT, self.config(**changed), NOW)
        with self.assertRaisesRegex(StateError, 'pricing'):
            _controller_activation(root, COMMIT, self.config(
                starts_at=(NOW + timedelta(hours=24)).isoformat(),
                expires_at=(NOW + timedelta(hours=25)).isoformat()),
                NOW + timedelta(hours=24))


if __name__ == '__main__':
    unittest.main()
