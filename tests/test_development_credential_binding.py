from dataclasses import replace
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import tempfile
from unittest import TestCase
from unittest.mock import AsyncMock, Mock, patch

import test_development_approval as fixtures
from factory_runtime.credential_issuance import CredentialIssuanceLedger, IssuanceAuthorization
from factory_runtime.development_composition import compose_task_host
from factory_runtime.development_profile import TaskExecutionProfile
from factory_runtime.provider_broker_service import ResolvedProviderTarget
from factory_runtime.workload_identity_response import RenewableCredentialBinding
from factory_state.model import StateError


class CredentialBindingTests(TestCase):
    def setUp(self):
        self.fixture = fixtures.ApprovalTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.now = datetime.now(timezone.utc)
        self.target = ResolvedProviderTarget('openai', 'gpt-5.6-sol', 'development-pinned-v1')
        self.auth = IssuanceAuthorization('sha256:'+'e'*64, 'idp-test', 'sa-test', self.target,
            self.now, self.now+timedelta(hours=1), 2, ('api.model.request',))
        self.exchange = AsyncMock()
        self.binding = self.make_binding(self.auth, 'first')
        spec = json.loads(self.fixture.f.options['contract_bytes'])
        self.profile = TaskExecutionProfile(spec['repository'], spec['task_id'],
            tuple(spec['allowed_paths']), ('python', '-m', 'unittest'))
        self.fixture.pins.update(model_id='gpt-5.6-sol', credential_source=self.binding.source_pin,
                                 execution_profile_digest=self.profile.digest)
        self.fixture.approval['pins'] = dict(self.fixture.pins)

    def make_binding(self, auth, name):
        ledger = CredentialIssuanceLedger(Path(self.temp.name)/(name+'.db'), auth,
                                          operator_authorized=True)
        return RenewableCredentialBinding(ledger, self.exchange)

    def compose(self, binding=None, authorized=True, supply=True):
        f = self.fixture
        return compose_task_host(f.f.path, profile=self.profile, approval=f.approval,
            expected_pins=f.pins, receipt_path=f.receipt, task=f.f.options['task'],
            contract_bytes=f.f.options['contract_bytes'], snapshot=f.f.options['snapshot'],
            pricing_source=Mock(), clock=lambda: self.now, owner_authorized=authorized,
            credential_binding=(binding or self.binding) if supply else None)

    def test_both_adapters_share_exact_source_without_exchange_or_env_access(self):
        with patch('factory_runtime.development_composition.EnvironmentProviderCredentialLeaseSource') as env:
            with patch('factory_runtime.development_approval.DevelopmentHost') as host:
                self.compose()
                options = host.call_args.kwargs
                self.assertIs(options['builder'].credential_source, options['reviewer'].credential_source)
                self.assertEqual(options['target'], self.target)
                self.assertEqual(options['builder'].policy.max_credential_ttl_seconds, 900)
            env.assert_not_called()
        self.exchange.assert_not_called()
        self.assertTrue(self.fixture.receipt.exists())

    def test_owner_gate_precedes_binding_composition(self):
        with patch.object(RenewableCredentialBinding, 'compose') as compose:
            with self.assertRaises(StateError):
                self.compose(authorized=False)
            compose.assert_not_called()
        self.assertFalse(self.fixture.receipt.exists())

    def test_missing_binding_never_falls_back_to_environment(self):
        with patch('factory_runtime.development_composition.EnvironmentProviderCredentialLeaseSource') as env:
            with self.assertRaises(StateError):
                self.compose(supply=False)
            env.assert_not_called()
        self.assertFalse(self.fixture.receipt.exists())

    def test_different_authorization_mapping_scopes_and_limits_need_new_pin(self):
        changes = [{'identity_provider_id': 'other'}, {'service_account_id': 'other'},
                   {'scopes': ('other',)}, {'maximum_exchanges': 3},
                   {'expires_at': self.now+timedelta(hours=2)},
                   {'approval_digest': 'sha256:'+'f'*64}, {'minimum_interval_seconds': 211}]
        for index, change in enumerate(changes):
            binding = self.make_binding(replace(self.auth, **change), str(index))
            self.assertNotEqual(binding.source_pin, self.binding.source_pin)
            with self.assertRaises(StateError):
                self.compose(binding)
        self.exchange.assert_not_called()
        self.assertFalse(self.fixture.receipt.exists())

    def test_renewal_target_must_match_host_even_with_updated_source_pin(self):
        binding = self.make_binding(replace(self.auth,
            target=replace(self.target, selector_version='other')), 'target')
        self.fixture.pins['credential_source'] = binding.source_pin
        self.fixture.approval['pins'] = dict(self.fixture.pins)
        with self.assertRaises(StateError):
            self.compose(binding)
        self.assertFalse(self.fixture.receipt.exists())

    def test_historical_environment_approval_cannot_authorize_renewal(self):
        self.fixture.approval['pins']['credential_source'] = 'env:FACTORY_OPENAI_API_KEY'
        with self.assertRaises(StateError):
            self.compose()
        self.exchange.assert_not_called()
        self.assertFalse(self.fixture.receipt.exists())

    def test_ledger_authorization_cannot_be_reassigned(self):
        with self.assertRaises(AttributeError):
            self.binding.ledger.authorization = replace(self.auth, maximum_exchanges=100)
        with self.assertRaises(AttributeError):
            self.binding.ledger.path = Path(self.temp.name)/'replacement.db'

    def test_new_ledger_cannot_reset_allowance_under_same_pin(self):
        replacement = self.make_binding(self.auth, 'replacement')
        self.assertNotEqual(replacement.source_pin, self.binding.source_pin)
        with self.assertRaises(StateError):
            self.compose(replacement)
        self.assertFalse(self.fixture.receipt.exists())


if __name__ == '__main__':
    __import__('unittest').main()
