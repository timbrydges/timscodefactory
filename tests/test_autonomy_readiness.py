import sys
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
from inspect_autonomy_readiness import FUNCTIONS, assess


class ReadinessTests(unittest.TestCase):
    def setUp(self):
        self.now = datetime(2026, 10, 1, tzinfo=timezone.utc)
        self.allowance = SimpleNamespace(pending_gates=(), activation_ready=True,
            pricing_observed_at=self.now, pricing_expires_at=self.now + timedelta(hours=1))
        self.receipt = {'source_commit': 'a' * 40,
            'reviewer_receipt_expires_at': (self.now + timedelta(minutes=30)).isoformat(),
            'status': 'INSPECTOR_REVIEW_ACCEPTED_AND_RECEIPT_PUBLISHED',
            'reviewer_receipt_signature_verified': True}
        self.functions = {role: {'State': 'Active', 'Timeout':
            {'controller': 300, 'builder': 180, 'broker': 120}[role],
            'Environment': {'Variables': {flag: 'true', binding: 'configured'}}}
            for role, (_, flag, binding) in FUNCTIONS.items()}

    def report(self):
        return assess(self.allowance, 'a' * 40, self.receipt, self.functions,
                      {'State': 'ENABLED'}, now=self.now)

    def test_metadata_cannot_authorize_activation_even_without_detected_blockers(self):
        result = self.report()
        self.assertEqual(result['blockers'], [])
        self.assertFalse(result['activation_authorized_by_audit'])
        self.assertEqual(result['status'], 'REQUIRES_FINAL_BOUND_DEPLOYMENT_VERIFICATION')

    def test_old_source_and_expired_receipt_cannot_be_reused(self):
        self.receipt['source_commit'] = 'b' * 40
        self.receipt['reviewer_receipt_expires_at'] = self.now.isoformat()
        self.assertIn('reviewer_receipt_source_differs', self.report()['blockers'])
        self.assertIn('reviewer_receipt_expired_or_invalid', self.report()['blockers'])

    def test_deployed_disabled_controller_has_actionable_blockers_without_env_leak(self):
        self.functions['controller'] = {'State': 'Active', 'Timeout': 10,
            'Environment': {'Variables': {'UNRELATED_SECRET': 'never-output'}}}
        result = self.report()
        self.assertIn('controller_execution_disabled', result['blockers'])
        self.assertIn('controller_activation_config_missing', result['blockers'])
        self.assertIn('controller_timeout_does_not_cover_builder', result['blockers'])
        self.assertNotIn('never-output', str(result))

    def test_stale_pricing_and_pending_contract_fail_closed(self):
        self.allowance.pricing_expires_at = self.now
        self.allowance.activation_ready = False
        self.allowance.pending_gates = ('guarded_schedule_activation',)
        result = self.report()
        for blocker in ('builder_pricing_not_current', 'operating_contract_not_active',
                        'guarded_schedule_activation'):
            self.assertIn(blocker, result['blockers'])

    def test_builder_cannot_expire_before_nested_broker(self):
        self.functions['builder']['Timeout'] = 60
        self.assertIn('builder_timeout_does_not_cover_broker', self.report()['blockers'])

    def test_shipped_timeouts_cover_provider_and_nested_invocations_without_retries(self):
        import json
        from factory_runtime.cloud_roles import lambda_client
        from factory_runtime.openai_provider import OpenAIProviderPolicy
        root = Path(__file__).resolve().parents[1]
        role = json.loads((root / 'infra/roles/functions.cloudformation.json').read_text())
        broker = json.loads((root / 'infra/acceptance/broker-canary.cloudformation.json').read_text())
        controller = json.loads((root / 'infra/acceptance/controller-disabled.cloudformation.json').read_text())
        builder_timeout = role['Resources']['BuilderFunction']['Properties']['Timeout']
        broker_timeout = broker['Resources']['BrokerFunction']['Properties']['Timeout']
        controller_timeout = controller['Resources']['ControllerFunction']['Properties']['Timeout']
        from unittest.mock import Mock, patch
        session = Mock()
        with patch.dict(sys.modules, {'botocore.config': SimpleNamespace(Config=SimpleNamespace)}):
            lambda_client(session)
        config = session.client.call_args.kwargs['config']
        self.assertEqual(config.retries['total_max_attempts'], 1)
        self.assertLess(OpenAIProviderPolicy().timeout_seconds, broker_timeout)
        self.assertLess(broker_timeout + 30, builder_timeout)
        self.assertLess(builder_timeout, config.read_timeout)
        self.assertLess(config.read_timeout + config.connect_timeout + 60, controller_timeout)


if __name__ == '__main__':
    unittest.main()
