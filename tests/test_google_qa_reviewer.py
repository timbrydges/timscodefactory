"""Google QA after the Anthropic Inspector: adapter, three-family rule and both-must-approve. No network."""
import asyncio
import json
import sys
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))

from factory_runtime import approved_models
from factory_runtime.development_provider import DevelopmentProviderSession
from factory_runtime.google_review_provider import GoogleQAPolicy, GoogleQAReviewInvoker, endpoint_for
from factory_runtime.openai_provider import (OpenAIProviderPricingError, OpenAIProviderProtocolError,
    ProviderCredentialLease, ProviderHTTPResponse)
from factory_runtime.provider_broker_service import ResolvedProviderTarget
from factory_runtime.provider_credentials import EnvironmentProviderCredentialLeaseSource
from factory_runtime.provider_http_transport import DirectGoogleTransport
from factory_state.model import StateError
import test_independent_reviewer as anthropic_fixtures
import test_openai_provider as provider_fixtures

QA = ResolvedProviderTarget('google', 'gemini-3.8-flash', 'test-v1')
TURN = anthropic_fixtures.TURN


class GoogleCredential:
    def __init__(self):
        self.calls = 0

    async def issue(self, *, target):
        self.calls += 1
        now = datetime.now(timezone.utc)
        return ProviderCredentialLease(token='AIza' + 'x' * 35, provider_family='google',
            audience='generativelanguage.googleapis.com', issued_at=now, expires_at=now + timedelta(minutes=5))


def generated(decision, *, model='gemini-3.8-flash', finish='STOP', usage=None):
    return {'modelVersion': model,
            'candidates': [{'finishReason': finish, 'content': {'role': 'model', 'parts': [{'text': json.dumps(decision)}]}}],
            'usageMetadata': usage or {'promptTokenCount': 3000, 'candidatesTokenCount': 200,
                                       'thoughtsTokenCount': 100, 'totalTokenCount': 3300}}


class Transport:
    def __init__(self, verdict='APPROVE', payload=None):
        self.verdict, self.payload, self.requests = verdict, payload, []

    async def post_json(self, *, endpoint, headers, body, timeout_seconds):
        request = json.loads(body)
        self.requests.append((endpoint, dict(headers), request))
        turn = json.loads(request['contents'][0]['parts'][0]['text'])
        findings = [] if self.verdict == 'APPROVE' else ['Missing test for empty input']
        payload = self.payload(turn) if self.payload else generated(
            {'review_input_digest': turn['review_input_digest'], 'verdict': self.verdict, 'findings': findings})
        return ProviderHTTPResponse(200, json.dumps(payload).encode())


def qa(transport, credential=None):
    return GoogleQAReviewInvoker(credential or GoogleCredential(), provider_fixtures.StaticPricingSource(),
                                 transport, policy=GoogleQAPolicy(live_enabled=True))


class GoogleAdapterTests(unittest.TestCase):
    def invoke(self, adapter, cap='0.25'):
        return asyncio.run(adapter.invoke(target=QA, turn=TURN, max_cost_usd=Decimal(cap),
                                          decision_schema_version='1'))

    def test_one_bounded_structured_request(self):
        transport = Transport()
        result = self.invoke(qa(transport))
        self.assertEqual(result.decision['verdict'], 'APPROVE')
        # 3000 x $4/M + (200 + 100 thinking) x $20/M
        self.assertEqual(result.cost_usd, Decimal('0.01800000'))
        [(endpoint, headers, body)] = transport.requests
        self.assertEqual(endpoint, endpoint_for('gemini-3.8-flash'))
        self.assertEqual(set(headers), {'x-goog-api-key', 'content-type', 'accept'})
        self.assertEqual(body['generationConfig']['responseMimeType'], 'application/json')
        self.assertEqual(body['generationConfig']['maxOutputTokens'], 4096)
        self.assertNotIn('tools', body)
        self.assertNotIn('cachedContent', body)

    def test_failures_are_named(self):
        def turned(**kwargs):
            return lambda turn: generated({'review_input_digest': turn['review_input_digest'],
                                           'verdict': 'APPROVE', 'findings': []}, **kwargs)
        cases = {'output_token_limit': turned(finish='MAX_TOKENS'), 'refusal': turned(finish='SAFETY'),
                 'model_mismatch': turned(model='gemini-other'),
                 'usage_invalid': turned(usage={'promptTokenCount': 1, 'candidatesTokenCount': 1,
                                                'totalTokenCount': 2, 'cachedContentTokenCount': 5}),
                 'review_fields_invalid': lambda turn: generated({'verdict': 'MAYBE'})}
        for code, payload in cases.items():
            with self.subTest(code=code):
                adapter = qa(Transport(payload=payload))
                with self.assertRaises(OpenAIProviderProtocolError) as caught:
                    self.invoke(adapter)
                self.assertEqual(caught.exception.failure_code, code)

    def test_worst_case_above_cap_stops_before_credential(self):
        credential, transport = GoogleCredential(), Transport()
        with self.assertRaises(OpenAIProviderPricingError):
            self.invoke(qa(transport, credential), cap='0.05')
        self.assertEqual((credential.calls, transport.requests), (0, []))

    def test_transport_route_and_key_binding_are_fixed(self):
        transport = DirectGoogleTransport(enabled=True)
        good = {'x-goog-api-key': 'k' * 39, 'content-type': 'application/json', 'accept': 'application/json'}
        for endpoint, headers in (('https://evil.example/v1beta/models/gemini-x:generateContent', good),
                                  (endpoint_for('gemini-3.8-flash'), {**good, 'x-extra': 'y'}),
                                  ('https://generativelanguage.googleapis.com/v1beta/models/gemini-x;rm:generateContent', good)):
            with self.assertRaises(OpenAIProviderProtocolError):
                asyncio.run(transport.post_json(endpoint=endpoint, headers=headers, body=b'{}', timeout_seconds=5))
        EnvironmentProviderCredentialLeaseSource(environment_variable='FACTORY_GOOGLE_API_KEY',
            provider_family='google', audience='generativelanguage.googleapis.com')
        with self.assertRaises(ValueError):
            EnvironmentProviderCredentialLeaseSource(environment_variable='FACTORY_GOOGLE_API_KEY')
        with self.assertRaises(ValueError):
            endpoint_for('gemini-x/../../other')

    def test_qa_list_is_validated(self):
        model, provider, prices = approved_models.resolve_qa({'qa_model': 'gemini-3.8-flash'})
        self.assertEqual(provider, 'google')
        self.assertIsNone(approved_models.resolve_qa({}))
        with self.assertRaises(ValueError):
            approved_models.resolve_qa({'qa_model': 'claude-opus-5-5'})


class ThreeFamilySessionTests(anthropic_fixtures.CrossProviderSessionTests):
    def qa_session(self, verdict='APPROVE', **overrides):
        self.qa_transport = Transport(verdict)
        options = dict(qa=qa(self.qa_transport), qa_target=QA, qa_cap=Decimal('0.25'), total_cap=Decimal('3'))
        options.update(overrides)
        return self.session(**options)

    def run_tick(self, session):
        self.f.runner.builder, self.f.runner.reviewer = session.build, session.review
        self.f.runner.enabled = True
        return self.f.tick()

    def test_inspector_then_qa_both_approve(self):
        result = self.run_tick(self.qa_session(enabled=True))
        self.assertEqual(result['status'], 'TICK_COMPLETED')
        self.assertEqual([e for e in self.events if e.endswith('.started')],
                         ['builder.started', 'reviewer.started', 'qa.started'])
        self.assertEqual(self.events['qa.started']['provider_family'], 'google')
        self.assertEqual(len(self.qa_transport.requests), 1)

    def test_qa_rejection_rejects_the_attempt_with_its_findings(self):
        result = self.run_tick(self.qa_session('REJECT', enabled=True))
        self.assertNotEqual(result['status'], 'TICK_COMPLETED')
        self.assertEqual(self.events['qa.completed']['proposal']['verdict'], 'REJECT')

    def test_qa_never_runs_after_an_inspector_rejection(self):
        self.review_transport.payload_for = lambda request: anthropic_fixtures.message(
            {'review_input_digest': json.loads(request['messages'][0]['content'])['review_input_digest'],
             'verdict': 'REJECT', 'findings': ['Wrong rounding']})
        self.run_tick(self.qa_session(enabled=True))
        self.assertNotIn('qa.started', self.events)
        self.assertEqual(self.qa_transport.requests, [])

    def test_qa_must_be_a_third_family_after_an_independent_inspector(self):
        openai_qa = ResolvedProviderTarget('openai', 'gpt-6.1-terra', 'test-v1')
        anthropic_qa = ResolvedProviderTarget('anthropic', 'claude-sonnet-5-5', 'test-v1')
        for overrides in (dict(qa_target=openai_qa), dict(qa_target=anthropic_qa), dict(qa_target=None),
                          dict(qa=self.reviewer)):
            with self.subTest(overrides=overrides), self.assertRaises(StateError):
                self.qa_session(**overrides)
        with self.assertRaises(StateError):  # The total must cover QA in every round.
            self.qa_session(total_cap=Decimal('1.24'), repair_rounds=0)


class QAPrepareTests(anthropic_fixtures.ReviewerPrepareTests):
    def setUp(self):
        super().setUp()
        task = json.loads(self.task.read_text())
        task['qa_model'] = 'gemini-3.8-flash'
        self.task.write_text(json.dumps(task))

    def test_qa_pins_cap_and_quote(self):
        self.prep.prepare(**self.kw, reviewer_input_price='4.00', reviewer_output_price='20.00',
                          qa_input_price='0.50', qa_output_price='3.00')
        pins = json.loads((self.tmp / 'out' / 'pins.json').read_text())
        pricing = json.loads((self.tmp / 'out' / 'pricing.json').read_text())
        self.assertEqual((pins['qa_model_id'], pins['qa_cap'], pins['total_cap']), ('gemini-3.8-flash', '0.25', '3.00'))
        self.assertEqual(pins['qa_credential_source'], 'env:FACTORY_GOOGLE_API_KEY')
        quotes = self.attempt.PinnedPricing(pricing)
        self.assertEqual(asyncio.run(quotes.quote(target=QA)).input_usd_per_million_tokens, Decimal('0.50'))

    def test_qa_prices_are_required(self):
        with self.assertRaises(ValueError):
            self.prep.prepare(**self.kw, reviewer_input_price='4.00', reviewer_output_price='20.00')

    # The inherited reviewer-only cases do not apply to a QA task.
    test_reviewer_pins_and_separate_quote = None
    test_reviewer_prices_are_required_and_bounded = None


if __name__ == '__main__':
    unittest.main()
