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
sys.path.insert(0, str(ROOT / 'scripts'))

from factory_runtime.autonomy_contract import load_autonomy_operating_allowance
from factory_state.model import StateError
from verify_sol_target_technical_enablement import verify as verify_target


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
        self.assertEqual(allowance.acceptance_repository_ruleset_id, 23853140)
        self.assertEqual(allowance.acceptance_required_status_check, 'test')
        self.assertEqual(allowance.maximum_total_cost, Decimal('5.00'))
        self.assertEqual(allowance.maximum_cost_per_call, Decimal('0.25'))
        self.assertEqual(allowance.maximum_provider_calls, 1)
        self.assertEqual(allowance.maximum_wall_clock_hours, 24)
        self.assertEqual(
            allowance.pricing_input_usd_per_million_tokens, Decimal('4.00'))
        self.assertEqual(
            allowance.pricing_output_usd_per_million_tokens, Decimal('20.00'))
        self.assertEqual(allowance.maximum_request_bytes_at_cost_cap, 42020)
        self.assertNotIn('fresh_provider_pricing', allowance.pending_gates)
        self.assertNotIn('ephemeral_provider_credential_path', allowance.pending_gates)
        self.assertNotIn('independent_pre_activation_review', allowance.pending_gates)
        self.assertNotIn('approved_target_technical_enablement', allowance.pending_gates)
        self.assertEqual(verify_target(ROOT)['model_calls'], 0)
        self.assertIn('guarded_operational_role_activation', allowance.pending_gates)
        self.assertFalse(allowance.production_release_authorized)
        self.assertFalse(allowance.activation_ready)
        self.assertEqual(allowance.status, 'GUARDED_COMMISSIONING')
        self.assertIsNotNone(allowance.commissioning_expires_at)

    def test_no_pending_gates_alone_does_not_activate_roles(self):
        def change(value):
            value['activation']['pending_gates'] = []
        with self.assertRaisesRegex(StateError, 'three unverified'):
            load_autonomy_operating_allowance(self.mutate(change))

    def test_active_status_requires_all_operational_gates(self):
        def change(value):
            value['status'] = 'ACTIVE'
            value['activation']['pending_gates'] = [
                'guarded_operational_role_activation',
                'live_controller_runtime_deployment',
                'guarded_schedule_activation',
            ]
        with self.assertRaisesRegex(StateError, 'pending gates'):
            load_autonomy_operating_allowance(self.mutate(change))

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

    def test_owner_exception_cannot_claim_independent_review_or_activation(self):
        for field, value in (('independent_review_performed', True),
                             ('operational_activation_authorized_by_this_exception', True),
                             ('model_calls_authorized_by_this_exception', 1)):
            with self.subTest(field=field):
                root = self.mutate(lambda _: None)
                path = root / 'factory/evidence/owner-review-exception-2026-09-29.json'
                record = json.loads(path.read_text())
                record[field] = value
                path.write_text(json.dumps(record))
                with self.assertRaisesRegex(StateError, 'owner review exception'):
                    load_autonomy_operating_allowance(root)

    def test_target_evidence_rejects_profile_drift_and_false_execution(self):
        for target in ('factory/profiles/provider-models.yaml',
                       'factory/evidence/sol-target-technical-enablement-2026-09-29.json'):
            with self.subTest(target=target):
                root = self.mutate(lambda _: None)
                path = root / target
                if target.endswith('.yaml'):
                    catalog = yaml.safe_load(path.read_text())
                    catalog['targets']['coding_primary_terra_live']['enabled'] = True
                    path.write_text(yaml.safe_dump(catalog))
                else:
                    record = json.loads(path.read_text())
                    record['model_calls'] = 1
                    path.write_text(json.dumps(record))
                with self.assertRaisesRegex(ValueError, 'Sol target technical evidence'):
                    verify_target(root)

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

    def test_pricing_reference_drift_fails_closed(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        root = Path(directory.name)
        shutil.copytree(ROOT / 'factory', root / 'factory')
        path = root / 'factory/evidence/openai-gpt-5.6-sol-pricing-quote-2026-10-01.json'
        evidence = json.loads(path.read_text())
        evidence['input_usd_per_million_tokens'] = '3.99'
        path.write_text(json.dumps(evidence))
        with self.assertRaisesRegex(StateError, 'pricing reference evidence'):
            load_autonomy_operating_allowance(root)


if __name__ == '__main__':
    unittest.main()
