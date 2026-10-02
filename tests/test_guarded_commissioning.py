"""Synthetic owner evidence only; no production authorization is created."""
import json
import shutil
import sys
import tempfile
import unittest
from dataclasses import replace
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import patch

import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / 'src'), str(ROOT / 'tests')]

from factory_runtime.autonomy import AutonomyActivation
from factory_runtime.autonomy_contract import (COMMISSIONING_EVIDENCE, COMMISSIONING_GATES,
    COMMISSIONING_ID, load_autonomy_operating_allowance)
from factory_runtime.autonomy_controller_lambda import _controller_activation
from factory_runtime.acceptance_broker_lambda import _activation
from factory_runtime.lambda_role import _builder_activation
from factory_runtime.operational_backend import AcceptanceOperationalBackend
from factory_state.dispatch import DispatchRequest
from factory_state.model import CONTROLLER_IDENTITY, StateError, TaskState
import test_operational_backend as fixtures


class CommissioningTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        shutil.copytree(ROOT / 'factory', self.root / 'factory')
        shutil.copytree(ROOT / 'docs', self.root / 'docs')
        self.path = self.root / 'factory/autonomy/operating-contract.yaml'
        self.contract = yaml.safe_load(self.path.read_text())
        self.now = datetime.fromisoformat(self.contract['pricing_reference']['observed_at'].replace('Z', '+00:00')) + timedelta(minutes=1)
        self.contract['status'] = 'GUARDED_COMMISSIONING'
        self.contract['approval']['commissioning_evidence'] = COMMISSIONING_EVIDENCE
        for key in ('autonomous_task_progression', 'schedule_activation', 'provider_calls'):
            self.contract['authority'][key] = 'ALLOW_GUARDED_COMMISSIONING'
        self.record = {
            'kind': 'guarded_commissioning_authorization', 'owner_identity': 'tim_brydges',
            'decision': 'AUTHORIZE_ONE_BOUNDED_COMMISSIONING_ACTIVATION',
            'activation_id': COMMISSIONING_ID, 'factory_id': 'tims-software-factory',
            'task_id': 'deterministic-text-fingerprint',
            'contract_sha256': self.contract['acceptance_target']['contract_sha256'],
            'model_id': 'gpt-5.6-sol', 'currency': 'USD',
            'maximum_provider_calls': 3, 'maximum_cost_usd_per_call': '0.25',
            'maximum_reserved_cost_usd': '0.75', 'maximum_wall_clock_hours': 24,
            'maximum_remediation_cycles': 0, 'maximum_retries': 0,
            'pending_gates': list(COMMISSIONING_GATES), 'claims_live_gates_verified': False,
            'fresh_owner_and_reviewer_signatures_required': True,
            'immutable_source_job_and_role_pins_required': True,
            'production_release_authorized': False,
            'authorization_text': 'TEST FIXTURE ONLY: isolated commissioning authorization',
            'authorized_at': self.now.isoformat().replace('+00:00', 'Z'),
            'expires_at': (self.now + timedelta(hours=1)).isoformat().replace('+00:00', 'Z'),
        }
        self.activation = AutonomyActivation(COMMISSIONING_ID, 'tims-software-factory',
            'deterministic-text-fingerprint', 'a' * 40, 'sha256:' + self.record['contract_sha256'],
            self.now, self.now + timedelta(minutes=45))
        self.save()

    def save(self):
        self.path.write_text(yaml.safe_dump(self.contract, sort_keys=False))
        (self.root / COMMISSIONING_EVIDENCE).write_text(json.dumps(self.record))

    def test_current_contract_still_denies_and_commissioning_never_claims_closed_gates(self):
        self.assertFalse(load_autonomy_operating_allowance(ROOT).permits_activation(self.activation))
        allowance = load_autonomy_operating_allowance(self.root)
        self.assertTrue(allowance.permits_activation(self.activation))
        self.assertFalse(allowance.activation_ready)
        self.assertFalse(allowance.production_release_authorized)
        self.assertEqual(allowance.pending_gates, COMMISSIONING_GATES)

    def test_other_activation_task_contract_or_window_cannot_reuse_authority(self):
        allowance = load_autonomy_operating_allowance(self.root)
        for changes in ({'activation_id': 'another-activation'}, {'task_id': 'another-task'},
                {'factory_id': 'another-factory'}, {'contract_digest': 'sha256:' + 'b' * 64},
                {'starts_at': self.now - timedelta(seconds=1)},
                {'expires_at': self.now + timedelta(hours=2)}):
            with self.subTest(changes=changes):
                self.assertFalse(allowance.permits_activation(replace(self.activation, **changes)))
        self.assertFalse(allowance.permits_activation(None))

    def test_missing_authorization_or_changed_financial_terms_fail_closed(self):
        (self.root / COMMISSIONING_EVIDENCE).unlink()
        with self.assertRaisesRegex(StateError, 'separate owner authorization'):
            load_autonomy_operating_allowance(self.root)
        original = dict(self.record)
        for changes in ({'maximum_provider_calls': 4}, {'maximum_retries': 1},
                {'production_release_authorized': True}, {'claims_live_gates_verified': True},
                {'activation_id': 'another'}, {'authorization_text': ''},
                {'expires_at': (self.now + timedelta(hours=25)).isoformat().replace('+00:00', 'Z')}):
            self.record = {**original, **changes}
            self.save()
            with self.subTest(changes=changes), self.assertRaises(StateError):
                load_autonomy_operating_allowance(self.root)

    def test_pending_gate_or_authority_changes_are_not_silently_accepted(self):
        self.contract['activation']['pending_gates'] = []
        self.save()
        with self.assertRaisesRegex(StateError, 'three unverified'):
            load_autonomy_operating_allowance(self.root)
        self.contract['activation']['pending_gates'] = list(COMMISSIONING_GATES)
        self.contract['authority']['provider_calls'] = 'ALLOW_AFTER_ALL_GATES'
        self.save()
        with self.assertRaisesRegex(StateError, 'authority differs'):
            load_autonomy_operating_allowance(self.root)

    def test_all_three_runtime_parsers_accept_only_the_bounded_activation(self):
        common = {key: getattr(self.activation, key) for key in (
            'activation_id', 'factory_id', 'task_id', 'source_commit', 'contract_digest')}
        common.update(starts_at=self.activation.starts_at.isoformat(), expires_at=self.activation.expires_at.isoformat())
        builder = {**common, 'broker_version_arn':
            'arn:aws:lambda:ca-central-1:666730517561:function:tims-factory-provider-broker:7'}
        controller = {**common, 'builder_version_arn':
            'arn:aws:lambda:ca-central-1:666730517561:function:tims-factory-builder:25',
            'job_versions': {'IMPLEMENTATION': {'version_id': 'test-job', 'sha256': 'sha256:' + 'd' * 64}}}
        self.assertEqual(_builder_activation(self.root, 'a' * 40, json.dumps(builder), self.now)[0], self.activation)
        self.assertEqual(_controller_activation(self.root, 'a' * 40, json.dumps(controller), self.now)[0], self.activation)
        with patch('factory_runtime.acceptance_broker_lambda.datetime') as clock:
            clock.now.return_value = self.now
            clock.fromisoformat.side_effect = datetime.fromisoformat
            self.assertEqual(_activation(json.dumps(common), source_commit='a' * 40, root=self.root), self.activation)
            with self.assertRaises(StateError):
                _activation(json.dumps({**common, 'activation_id': 'another'}), source_commit='a' * 40, root=self.root)
        for parse, config in ((_builder_activation, builder), (_controller_activation, controller)):
            with self.assertRaises(StateError):
                parse(self.root, 'a' * 40, json.dumps({**config, 'activation_id': 'another'}), self.now)

    def test_backend_keeps_budget_and_disabled_guards_for_commissioning(self):
        budget, executor = fixtures.Budget(), fixtures.Executor()
        backend = AcceptanceOperationalBackend(self.root, self.activation, budget, executor,
            enabled=True, clock=lambda: self.now)
        state = TaskState('tims-software-factory', self.activation.task_id, 'IMPLEMENTATION', 1, self.now, CONTROLLER_IDENTITY)
        request = DispatchRequest('lease-123', 'autonomy', 'acceptance', 'a' * 40,
            self.activation.contract_digest, 'sha256:' + 'c' * 64)
        with self.assertRaisesRegex(StateError, 'reservation is missing'):
            backend.execute(state, request, dispatch_id='dispatch-1', input_bytes=b'input')
        self.assertEqual(executor.calls, [])
        backend.reserve(state, request, dispatch_id='dispatch-1', now=self.now)
        self.assertEqual(budget.calls[0]['maximum_provider_calls'], 3)
        self.assertEqual(str(budget.calls[0]['maximum_cost_usd']), '0.25')
        self.assertEqual(backend.execute(state, request, dispatch_id='dispatch-1', input_bytes=b'input'), b'accepted')
        backend.enabled = False
        with self.assertRaisesRegex(StateError, 'disabled'):
            backend.check_activation(state, request, now=self.now)
