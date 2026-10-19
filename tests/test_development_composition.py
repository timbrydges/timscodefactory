from datetime import datetime, timezone
from types import SimpleNamespace
from unittest import TestCase
from unittest.mock import patch, Mock
from factory_runtime.development_composition import compose_bonus_host
from factory_state.model import StateError


class CompositionTests(TestCase):
    def setUp(self):
        self.pins = dict(credential_source='env:FACTORY_OPENAI_API_KEY', model_id='gpt-5.6-sol',
            repository='timbrydges/bonus-library', image_ref='sha256:'+'b'*64,
            max_request_bytes=42020, max_output_tokens=4096,
            builder_cap='0.25', reviewer_cap='0.25', total_cap='0.50')
        self.options = dict(approval={}, expected_pins=self.pins, receipt_path='unused',
            task=SimpleNamespace(task_id='bonus-library-pagination', activation_id='test'),
            contract_bytes=b'{}', snapshot=None, pricing_source=Mock(),
            clock=lambda: datetime.now(timezone.utc))

    def test_default_refuses_before_host_or_secret_access(self):
        with patch('factory_runtime.development_composition.compose_approved_host') as host:
            with self.assertRaises(StateError): compose_bonus_host('unused', **self.options)
            host.assert_not_called()

    def test_exact_credential_source_and_image_bound_without_reading_secret(self):
        with patch('factory_runtime.development_composition.compose_approved_host') as host:
            compose_bonus_host('unused', owner_authorized=True, **self.options)
            args = host.call_args.kwargs
            builder, reviewer = args['builder'], args['reviewer']
            self.assertIs(builder.credential_source, reviewer.credential_source)
            self.assertEqual(builder.credential_source.environment_variable, 'FACTORY_OPENAI_API_KEY')
            self.assertEqual(builder.policy.workload, 'task_implementation')
            self.assertEqual(reviewer.policy.workload, 'task_review')
            self.assertEqual(builder.policy.timeout_seconds, 180)
            self.assertEqual(reviewer.policy.timeout_seconds, 180)
            candidate = Mock()
            args['request_for'](candidate)
            self.assertEqual(candidate.request.call_args.kwargs['command'],
                ('node', '--experimental-strip-types', '--test', 'tests/library-pagination.test.mjs'))
            self.options['pricing_source'].quote.assert_not_called()

    def test_other_secret_or_provider_is_rejected(self):
        for key, value in [('credential_source', 'env:OTHER_KEY'), ('model_id', 'other-model')]:
            original = self.pins[key]
            self.pins[key] = value
            with self.assertRaises(StateError):
                compose_bonus_host('unused', owner_authorized=True, **self.options)
            self.pins[key] = original
