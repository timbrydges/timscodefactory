import copy
import json
import shutil
import sys
import tempfile
import unittest
from decimal import Decimal
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))

from factory_runtime.autonomy_contract import load_autonomy_operating_allowance
from factory_state.model import StateError


class AutonomyOperatingContractTests(unittest.TestCase):
    def test_exact_owner_authorized_allowance_is_recorded_but_not_active(self):
        allowance = load_autonomy_operating_allowance(ROOT)
        self.assertEqual(allowance.contract_id, 'tims-factory-autonomy-acceptance-001')
        self.assertEqual(allowance.provider_family, 'openai')
        self.assertEqual(allowance.model_id, 'gpt-5.6-sol')
        self.assertEqual(allowance.target_alias, 'coding_primary_sol_live')
        self.assertEqual(
            allowance.acceptance_repository,
            'timbrydges/tims-factory-autonomy-acceptance')
        self.assertEqual(allowance.acceptance_repository_id, 1382496429)
        self.assertEqual(
            allowance.acceptance_contract_commit,
            'fcb4c535d4ea00962b26db14f59e34917ef2389f')
        self.assertEqual(
            allowance.acceptance_contract_sha256,
            '7ca5363f88bc43e31436e1c8640bb9516a705aa07dda82519a690a9301a9b9fa')
        self.assertEqual(allowance.acceptance_task_id, 'deterministic-text-fingerprint')
        self.assertEqual(allowance.maximum_total_cost, Decimal('5.00'))
        self.assertEqual(allowance.maximum_cost_per_call, Decimal('0.25'))
        self.assertEqual(allowance.maximum_provider_calls, 3)
        self.assertEqual(allowance.maximum_wall_clock_hours, 24)
        self.assertFalse(allowance.production_release_authorized)
        self.assertFalse(allowance.activation_ready)

    def mutate(self, callback):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        root = Path(directory.name)
        shutil.copytree(ROOT / 'factory', root / 'factory')
        shutil.copytree(ROOT / 'docs', root / 'docs')
        path = root / 'factory/autonomy/operating-contract.yaml'
        document = yaml.safe_load(path.read_text())
        callback(document)
        path.write_text(yaml.safe_dump(document, sort_keys=False))
        return root

    def test_budget_model_release_and_owner_drift_fail_closed(self):
        changes = (
            lambda value: value['limits'].__setitem__('maximum_total_cost', '5.01'),
            lambda value: value['provider'].__setitem__('model_id', 'other-model'),
            lambda value: value['authority'].__setitem__('production_release', 'ALLOW'),
            lambda value: value['approval'].__setitem__('owner_identity', 'someone_else'),
        )
        for change in changes:
            with self.subTest(change=change):
                with self.assertRaises(StateError):
                    load_autonomy_operating_allowance(self.mutate(change))

    def test_active_status_is_rejected_while_any_gate_is_pending(self):
        def change(value):
            value['status'] = 'ACTIVE'
        with self.assertRaisesRegex(StateError, 'pending gates'):
            load_autonomy_operating_allowance(self.mutate(change))

    def test_authorization_evidence_must_match_every_financial_term(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        root = Path(directory.name)
        shutil.copytree(ROOT / 'factory', root / 'factory')
        path = root / 'factory/evidence/autonomy-financial-authorization-2026-09-23.json'
        evidence = json.loads(path.read_text())
        evidence['maximum_provider_calls'] = 4
        path.write_text(json.dumps(evidence))
        with self.assertRaisesRegex(StateError, 'differs'):
            load_autonomy_operating_allowance(root)

    def test_verified_gate_cannot_reference_missing_evidence(self):
        def change(value):
            value['activation']['verified_gates']['cloud_role_transport']['evidence'] = (
                'factory/evidence/not-real.json')
        with self.assertRaisesRegex(StateError, 'evidence is missing'):
            load_autonomy_operating_allowance(self.mutate(change))

    def test_acceptance_target_evidence_drift_fails_closed(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        root = Path(directory.name)
        shutil.copytree(ROOT / 'factory', root / 'factory')
        path = root / 'factory/evidence/autonomy-acceptance-repository-2026-09-23.json'
        evidence = json.loads(path.read_text())
        evidence['contract_sha256'] = '0' * 64
        path.write_text(json.dumps(evidence))
        with self.assertRaisesRegex(StateError, 'acceptance target evidence'):
            load_autonomy_operating_allowance(root)


if __name__ == '__main__':
    unittest.main()
