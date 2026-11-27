"""Independent Anthropic reviewer: adapter, cross-provider rule and attempt pins. No network."""
import asyncio
import json
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))

from factory_runtime import approved_models
from factory_runtime.anthropic_provider import (
    AnthropicMessagesReviewInvoker, AnthropicReviewPolicy, ANTHROPIC_VERSION)
from factory_runtime.development_provider import DevelopmentProviderSession
from factory_runtime.openai_provider import (
    OpenAIProviderPricingError, OpenAIProviderProtocolError, OpenAIResponsesProviderInvoker,
    OpenAIProviderPolicy, ProviderCredentialLease, ProviderHTTPResponse)
from factory_runtime.provider_broker_service import ResolvedProviderTarget
from factory_runtime.provider_credentials import EnvironmentProviderCredentialLeaseSource
from factory_runtime.provider_http_transport import DirectAnthropicTransport
from factory_state.model import StateError
import test_development_runner as runner_fixtures
import test_openai_provider as provider_fixtures

REVIEWER = ResolvedProviderTarget(provider_family='anthropic', model_id='claude-opus-5-5',
                                  selector_version='test-v1')
TURN = {'kind': 'factory_task_review_v1', 'review_input_digest': 'sha256:' + 'a' * 64}


class AnthropicCredential:
    def __init__(self):
        self.calls = 0

    async def issue(self, *, target):
        self.calls += 1
        now = datetime.now(timezone.utc)
        return ProviderCredentialLease(token='sk-ant-test-secret-1234567890', provider_family='anthropic',
            audience='api.anthropic.com', issued_at=now, expires_at=now + timedelta(minutes=5))


def message(decision, *, model='claude-opus-5-5', stop='end_turn', usage=None):
    return {'type': 'message', 'model': model, 'stop_reason': stop,
            'content': [{'type': 'thinking', 'thinking': '', 'signature': 'x'},
                        {'type': 'text', 'text': json.dumps(decision)}],
            'usage': usage or {'input_tokens': 2000, 'output_tokens': 300}}


class Transport:
    def __init__(self, payload_for):
        self.payload_for, self.requests = payload_for, []

    async def post_json(self, *, endpoint, headers, body, timeout_seconds):
        self.requests.append((endpoint, dict(headers), json.loads(body)))
        return ProviderHTTPResponse(200, json.dumps(self.payload_for(json.loads(body))).encode())


def approve(request):
    turn = json.loads(request['messages'][0]['content'])
    return message({'review_input_digest': turn['review_input_digest'], 'verdict': 'APPROVE', 'findings': []})


def reviewer(transport, credential=None, **policy):
    return AnthropicMessagesReviewInvoker(credential or AnthropicCredential(),
        provider_fixtures.StaticPricingSource(), transport,
        policy=AnthropicReviewPolicy(live_enabled=True, **policy))


class AnthropicAdapterTests(unittest.TestCase):
    def invoke(self, adapter, cap='0.25'):
        return asyncio.run(adapter.invoke(target=REVIEWER, turn=TURN,
                                          max_cost_usd=Decimal(cap), decision_schema_version='1'))

    def test_one_bounded_structured_review_request(self):
        transport = Transport(approve)
        result = self.invoke(reviewer(transport))
        self.assertEqual(result.decision['verdict'], 'APPROVE')
        # 2000 x $4/M + 300 x $20/M
        self.assertEqual(result.cost_usd, Decimal('0.01400000'))
        [(endpoint, headers, body)] = transport.requests
        self.assertEqual(endpoint, 'https://api.anthropic.com/v1/messages')
        self.assertEqual(headers['anthropic-version'], ANTHROPIC_VERSION)
        self.assertEqual(set(headers), {'x-api-key', 'anthropic-version', 'content-type', 'accept'})
        self.assertEqual(body['model'], 'claude-opus-5-5')
        self.assertEqual(body['max_tokens'], 4096)
        self.assertEqual(body['output_config']['format']['type'], 'json_schema')
        self.assertEqual(body['output_config']['effort'], 'low')
        for absent in ('tools', 'tool_choice', 'thinking', 'temperature', 'cache_control'):
            self.assertNotIn(absent, body)

    def test_failures_are_named_and_consumed(self):
        cases = {'output_token_limit': lambda r: message({}, stop='max_tokens'),
                 'refusal': lambda r: message({}, stop='refusal'),
                 'model_mismatch': lambda r: {**approve(r), 'model': 'claude-sonnet-5-5'},
                 'usage_invalid': lambda r: {**approve(r), 'usage': {'input_tokens': 1, 'output_tokens': 1,
                                                                     'cache_read_input_tokens': 5}},
                 'review_fields_invalid': lambda r: message({'verdict': 'MAYBE'})}
        for code, payload in cases.items():
            with self.subTest(code=code):
                adapter = reviewer(Transport(payload))
                with self.assertRaises(OpenAIProviderProtocolError) as caught:
                    self.invoke(adapter)
                self.assertEqual(caught.exception.failure_code, code)
                self.assertEqual(adapter.invocation_count, 0)

    def test_worst_case_above_cap_stops_before_credential(self):
        credential, transport = AnthropicCredential(), Transport(approve)
        with self.assertRaises(OpenAIProviderPricingError):
            self.invoke(reviewer(transport, credential), cap='0.05')
        self.assertEqual((credential.calls, transport.requests), (0, []))

    def test_disabled_policy_and_wrong_family_never_send(self):
        transport = Transport(approve)
        adapter = AnthropicMessagesReviewInvoker(AnthropicCredential(), provider_fixtures.StaticPricingSource(),
                                                 transport)
        with self.assertRaises(Exception):
            self.invoke(adapter)
        with self.assertRaises(OpenAIProviderProtocolError):
            asyncio.run(reviewer(transport).invoke(target=provider_fixtures.TARGET, turn=TURN,
                max_cost_usd=Decimal('1'), decision_schema_version='1'))
        self.assertEqual(transport.requests, [])
        with self.assertRaises(ValueError):
            AnthropicReviewPolicy(workload='task_implementation')

    def test_transport_and_credential_bindings_are_fixed(self):
        transport = DirectAnthropicTransport(enabled=True)
        good = {'x-api-key': 'k' * 20, 'anthropic-version': ANTHROPIC_VERSION,
                'content-type': 'application/json', 'accept': 'application/json'}
        for endpoint, headers in (('https://api.openai.com/v1/responses', good),
                                  ('https://api.anthropic.com/v1/messages', {**good, 'x-extra': 'y'})):
            with self.assertRaises(OpenAIProviderProtocolError):
                asyncio.run(transport.post_json(endpoint=endpoint, headers=headers, body=b'{}', timeout_seconds=5))
        EnvironmentProviderCredentialLeaseSource(environment_variable='FACTORY_ANTHROPIC_API_KEY',
            provider_family='anthropic', audience='api.anthropic.com')
        for kwargs in (dict(environment_variable='FACTORY_ANTHROPIC_API_KEY'),
                       dict(provider_family='anthropic', audience='api.anthropic.com')):
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                EnvironmentProviderCredentialLeaseSource(**kwargs)


class CrossProviderSessionTests(unittest.TestCase):
    def setUp(self):
        self.f = runner_fixtures.DevelopmentRunnerTests()
        self.f.setUp()
        self.addCleanup(self.f.doCleanups)
        self.events = {}
        outer = self
        class BuilderTransport:
            async def post_json(self, *, endpoint, headers, body, timeout_seconds):
                return ProviderHTTPResponse(200, json.dumps(
                    provider_fixtures.provider_payload({'decision': outer.f.f.decision})).encode())
        self.builder = OpenAIResponsesProviderInvoker(provider_fixtures.CountingCredentialSource(),
            provider_fixtures.StaticPricingSource(), BuilderTransport(),
            policy=OpenAIProviderPolicy(live_enabled=True, workload='task_implementation'))
        self.review_transport = Transport(approve)
        self.reviewer = reviewer(self.review_transport)

    def session(self, **overrides):
        options = dict(builder=self.builder, reviewer=self.reviewer, target=provider_fixtures.TARGET,
            builder_cap=Decimal('1'), reviewer_cap=Decimal('0.25'), total_cap=Decimal('2'),
            journal=lambda name, evidence: self.events.__setitem__(name, evidence),
            reviewer_target=REVIEWER)
        options.update(overrides)
        return DevelopmentProviderSession(**options)

    def test_openai_builder_reviewed_by_anthropic_end_to_end(self):
        session = self.session(enabled=True)
        self.f.runner.builder, self.f.runner.reviewer = session.build, session.review
        self.f.runner.enabled = True
        self.assertEqual(self.f.tick()['status'], 'TICK_COMPLETED')
        self.assertEqual(self.events['builder.started']['provider_family'], 'openai')
        self.assertEqual(self.events['reviewer.started']['provider_family'], 'anthropic')
        self.assertEqual(self.events['reviewer.started']['model_id'], 'claude-opus-5-5')
        self.assertEqual(self.events['reviewer.completed']['cost_usd'], '0.01400000')
        self.assertEqual(len(self.review_transport.requests), 1)
        self.assertNotIn('sk-ant-test-secret', json.dumps(self.events))

    def test_builder_family_can_never_review_its_own_output(self):
        openai_reviewer = OpenAIResponsesProviderInvoker(provider_fixtures.CountingCredentialSource(),
            provider_fixtures.StaticPricingSource(), self.review_transport,
            policy=OpenAIProviderPolicy(live_enabled=True, workload='task_review'))
        same_family = ResolvedProviderTarget('openai', 'gpt-6.1-terra', 'test-v1')
        for overrides in (dict(reviewer_target=same_family), dict(reviewer=openai_reviewer),
                          dict(reviewer_target=provider_fixtures.TARGET),
                          dict(reviewer=openai_reviewer, reviewer_target=same_family)):
            with self.subTest(overrides=overrides), self.assertRaises(StateError):
                self.session(**overrides)
        with self.assertRaises(StateError):
            self.session(reviewer_target=None)  # Anthropic adapter needs an Anthropic target.


class ReviewerPinTests(unittest.TestCase):
    def test_reviewer_list_is_validated(self):
        self.assertEqual(approved_models.resolve_reviewer({}), None)
        model, provider, prices = approved_models.resolve_reviewer({'reviewer_model': 'claude-opus-5-5'})
        self.assertEqual((model, provider), ('claude-opus-5-5', 'anthropic'))
        with self.assertRaises(ValueError):
            approved_models.resolve_reviewer({'reviewer_model': 'gpt-6.1-terra'})
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'models.json'
            data = json.loads(approved_models.MODELS.read_text())
            data['reviewers']['claude-opus-5-5']['max_output_usd_per_million_tokens'] = '25.00'
            path.write_text(json.dumps(data))
            with self.assertRaises(ValueError):
                approved_models.load_reviewers(path)
            data['reviewers'] = {'x-model': {'provider': 'openai', 'max_input_usd_per_million_tokens': '1',
                                             'max_output_usd_per_million_tokens': '1'}}
            path.write_text(json.dumps(data))
            with self.assertRaises(ValueError):
                approved_models.load_reviewers(path)

    def test_review_worst_case_fits_both_reviewer_caps(self):
        # Opus 5.5 at the approved maximum: request bytes x $4/M + 4096 x $20/M.
        for request_bytes, cap in ((42020, Decimal('0.25')), (96000, Decimal('0.50'))):
            adapter = reviewer(Transport(approve), max_request_bytes=request_bytes)
            worst = (Decimal(request_bytes) * 4 + Decimal(adapter.policy.max_output_tokens) * 20) / 1_000_000
            self.assertLessEqual(worst, cap)


class ReviewerCompositionTests(unittest.TestCase):
    def setUp(self):
        from types import SimpleNamespace
        from unittest.mock import Mock
        self.pins = dict(credential_source='env:FACTORY_OPENAI_API_KEY', model_id='gpt-5.6-sol',
            repository='timbrydges/bonus-library', image_ref='sha256:' + 'b' * 64,
            max_request_bytes=42020, max_output_tokens=16384,
            builder_cap='0.50', reviewer_cap='0.25', total_cap='0.75',
            reviewer_model_id='claude-opus-5-5', reviewer_credential_source='env:FACTORY_ANTHROPIC_API_KEY')
        self.options = dict(approval={}, expected_pins=self.pins, receipt_path='unused',
            task=SimpleNamespace(task_id='bonus-library-pagination', activation_id='test'),
            contract_bytes=b'{}', snapshot=None, pricing_source=Mock(),
            clock=lambda: datetime.now(timezone.utc), owner_authorized=True)

    def compose(self):
        from unittest.mock import patch
        from factory_runtime.development_composition import compose_bonus_host
        with patch('factory_runtime.development_composition.compose_approved_host') as host:
            compose_bonus_host('unused', **self.options)
            return host.call_args.kwargs

    def test_pinned_reviewer_is_an_anthropic_adapter_with_its_own_key(self):
        args = self.compose()
        builder, review = args['builder'], args['reviewer']
        self.assertIsInstance(review, AnthropicMessagesReviewInvoker)
        self.assertEqual(args['reviewer_target'].provider_family, 'anthropic')
        self.assertEqual(args['reviewer_target'].model_id, 'claude-opus-5-5')
        self.assertEqual(review.credential_source.environment_variable, 'FACTORY_ANTHROPIC_API_KEY')
        self.assertEqual(builder.credential_source.environment_variable, 'FACTORY_OPENAI_API_KEY')
        self.assertEqual(review.policy.max_output_tokens, 4096)
        self.assertIsInstance(review.transport, DirectAnthropicTransport)
        self.options['pricing_source'].quote.assert_not_called()

    def test_unapproved_reviewer_or_key_fails_closed(self):
        for key, value in (('reviewer_model_id', 'claude-fable-5-2'),
                           ('reviewer_credential_source', 'env:FACTORY_OPENAI_API_KEY')):
            with self.subTest(key=key):
                original, self.pins[key] = self.pins[key], value
                with self.assertRaises(StateError):
                    self.compose()
                self.pins[key] = original

    def test_approval_binds_the_reviewer_pins(self):
        from factory_runtime.development_approval import approval_pins_match
        pins = dict(source_commit='a', contract_digest='b', repository='r', target_commit='c',
                    image_ref='i', model_id='m', attempt_id='x', credential_source='s',
                    builder_cap='1', reviewer_cap='1', total_cap='2', max_request_bytes=1,
                    max_output_tokens=1)
        with_reviewer = dict(pins, reviewer_model_id='claude-opus-5-5',
                             reviewer_credential_source='env:FACTORY_ANTHROPIC_API_KEY')
        self.assertTrue(approval_pins_match({'pins': with_reviewer, 'expires_at': 'e'}, with_reviewer))
        with self.assertRaises(StateError):
            approval_pins_match({'pins': pins, 'expires_at': 'e'}, with_reviewer)
        with self.assertRaises(StateError):  # A reviewer pin without its credential pin.
            partial = dict(pins, reviewer_model_id='claude-opus-5-5')
            approval_pins_match({'pins': partial, 'expires_at': 'e'}, partial)


class ReviewerPrepareTests(unittest.TestCase):
    def setUp(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location('prep_r', ROOT / 'scripts' / 'prepare_development_attempt.py')
        self.prep = importlib.util.module_from_spec(spec); spec.loader.exec_module(self.prep)
        spec = importlib.util.spec_from_file_location('attempt_r', ROOT / 'scripts' / 'development_attempt.py')
        self.attempt = importlib.util.module_from_spec(spec); spec.loader.exec_module(self.attempt)
        tmp = tempfile.TemporaryDirectory(); self.addCleanup(tmp.cleanup)
        self.tmp = Path(tmp.name).resolve()
        task = json.loads(self.prep.TASK.read_text())
        task['reviewer_model'] = 'claude-opus-5-5'
        self.task = self.tmp / 'task.json'
        self.task.write_text(json.dumps(task))
        self.kw = dict(output=self.tmp / 'out', attempt_id='pagination-001',
            image_ref='docker.io/library/node@sha256:' + 'a' * 64, source_config_sha256='sha256:' + 'b' * 64,
            manifest=task.get('source_manifest_digest', 'sha256:' + 'c' * 64),
            input_price='4.00', output_price='20.00', pricing_source='owner-checked',
            now=datetime(2026, 11, 27, tzinfo=timezone.utc), hours=12, source_commit='d' * 40,
            task=self.task)

    def test_reviewer_pins_and_separate_quote(self):
        self.prep.prepare(**self.kw, reviewer_input_price='4.00', reviewer_output_price='20.00')
        pins = json.loads((self.tmp / 'out' / 'pins.json').read_text())
        pricing = json.loads((self.tmp / 'out' / 'pricing.json').read_text())
        self.assertEqual(pins['reviewer_model_id'], 'claude-opus-5-5')
        self.assertEqual(pins['reviewer_credential_source'], 'env:FACTORY_ANTHROPIC_API_KEY')
        self.assertEqual(pins['reviewer_cap'], '0.25')
        quotes = self.attempt.PinnedPricing(pricing)
        self.assertEqual(asyncio.run(quotes.quote(target=REVIEWER)).model_id, 'claude-opus-5-5')
        self.assertEqual(asyncio.run(quotes.quote(target=provider_fixtures.TARGET)).model_id, 'gpt-5.6-sol')

    def test_reviewer_prices_are_required_and_bounded(self):
        for prices in ({}, {'reviewer_input_price': '4.00'},
                       {'reviewer_input_price': '4.00', 'reviewer_output_price': '25.00'}):
            with self.subTest(prices=prices), self.assertRaises(ValueError):
                self.prep.prepare(**self.kw, **prices)
            self.assertFalse((self.tmp / 'out').exists())


class OwnerKeyTests(unittest.TestCase):
    def test_keys_cannot_be_swapped(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location('owner_r', ROOT / 'scripts' / 'run_owner_attempt.py')
        owner = importlib.util.module_from_spec(spec); spec.loader.exec_module(owner)
        openai_key, anthropic_key = 'sk-proj-' + 'a' * 40, 'sk-ant-api03-' + 'b' * 40
        self.assertTrue(owner.KEY.fullmatch(openai_key))
        self.assertFalse(owner.KEY.fullmatch(anthropic_key))
        self.assertTrue(owner.ANTHROPIC_KEY.fullmatch(anthropic_key))
        self.assertFalse(owner.ANTHROPIC_KEY.fullmatch(openai_key))
        class Ops:
            def __init__(self, clip): self.clip, self.prompts = clip, []
            def wait_for_key_copy(self, provider='OpenAI'): self.prompts.append(provider)
            def read_clipboard(self): return self.clip
            def clear_clipboard(self): pass
        import os
        from unittest.mock import patch
        with patch.dict(os.environ, {}, clear=True):
            ops = Ops(anthropic_key)
            self.assertEqual(owner.load_reviewer_key(ops), anthropic_key)
            self.assertEqual(ops.prompts, ['Anthropic'])
            with self.assertRaises(ValueError):
                owner.load_reviewer_key(Ops(openai_key))


if __name__ == '__main__':
    unittest.main()
