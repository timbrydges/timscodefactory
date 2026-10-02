import json
import sys
import unittest
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))

from factory_runtime.acceptance_openai import AcceptanceOpenAIProvider
from factory_runtime.openai_provider import (
    OpenAIProviderDisabledError, OpenAIProviderPolicy, OpenAIProviderPricingError,
    OpenAIProviderProtocolError, ProviderCredentialLease, ProviderHTTPResponse,
    ProviderPricingQuote,
)


class Credentials:
    calls = 0

    async def issue(self, *, target):
        self.calls += 1
        now = datetime.now(timezone.utc)
        return ProviderCredentialLease('fake-credential-123456789', 'openai', 'api.openai.com',
                                       now - timedelta(seconds=1), now + timedelta(minutes=5))


class Pricing:
    input_price = Decimal('4')
    output_price = Decimal('20')
    age = timedelta(minutes=1)

    async def quote(self, *, target):
        now = datetime.now(timezone.utc)
        return ProviderPricingQuote(target.model_id, self.input_price, self.output_price,
                                    now - self.age, now + timedelta(hours=1), 'test')


class Transport:
    calls = 0
    payload = None
    status_code = 200

    async def post_json(self, *, endpoint, headers, body, timeout_seconds):
        self.calls += 1
        self.request = json.loads(body)
        self.endpoint = endpoint
        self.headers = dict(headers)
        return ProviderHTTPResponse(self.status_code, json.dumps(self.payload).encode())


def response(*, model='gpt-5.6-sol', output_type='message', output_tokens=100):
    return {'model': model, 'status': 'completed', 'error': None,
            'incomplete_details': None, 'usage': {'input_tokens': 100, 'output_tokens': output_tokens},
            'output': [{'type': output_type, 'role': 'assistant',
                        'content': [{'type': 'output_text', 'text': 'bounded answer'}]}]}


class AcceptanceOpenAITests(unittest.TestCase):
    def setUp(self):
        self.credentials, self.pricing, self.transport = Credentials(), Pricing(), Transport()
        self.transport.payload = response()
        self.adapter = AcceptanceOpenAIProvider(self.credentials, self.pricing, self.transport)

    def call(self):
        return self.adapter.generate(input_bytes=b'bounded input', model_id='gpt-5.6-sol',
                                     maximum_cost_usd=Decimal('0.25'))

    def test_disabled_before_credentials_or_transport(self):
        with self.assertRaises(OpenAIProviderDisabledError):
            self.call()
        self.assertEqual((self.credentials.calls, self.transport.calls), (0, 0))

    def test_one_bounded_call_and_conservative_cost(self):
        self.adapter.policy = OpenAIProviderPolicy(live_enabled=True)
        output, cost = self.call()
        self.assertEqual(output, b'bounded answer')
        self.assertEqual(cost, Decimal('0.00250000'))
        self.assertEqual((self.credentials.calls, self.transport.calls), (1, 1))
        self.assertEqual(self.transport.request['model'], 'gpt-5.6-sol')
        self.assertFalse(self.transport.request['store'])
        self.assertNotIn('tools', self.transport.request)
        self.assertEqual(self.transport.endpoint, 'https://api.openai.com/v1/responses')
        context = json.loads(self.transport.request['input'])
        self.assertEqual(context['request'], 'bounded input')
        self.assertEqual(context['contract']['required_test_command'],
                         ['python', '-m', 'unittest', 'discover', '-s', 'tests', '-v'])
        self.assertEqual(context['source']['files'],
                         {'fingerprint.py': None, 'tests/test_fingerprint.py': None})
        self.assertIn('complete Python source strings', self.transport.request['instructions'])

    def test_stale_and_expensive_quote_fail_before_credential(self):
        self.adapter.policy = OpenAIProviderPolicy(live_enabled=True)
        self.pricing.age = timedelta(days=2)
        with self.assertRaises(OpenAIProviderPricingError):
            self.call()
        self.pricing.age = timedelta(minutes=1)
        self.pricing.output_price = Decimal('100')
        with self.assertRaises(OpenAIProviderPricingError):
            self.call()
        self.assertEqual((self.credentials.calls, self.transport.calls), (0, 0))

    def test_missing_context_stops_before_credentials_and_provider_call(self):
        import tempfile
        from factory_state.model import StateError
        self.adapter.policy = OpenAIProviderPolicy(live_enabled=True)
        with tempfile.TemporaryDirectory() as directory:
            self.adapter.repository_root = Path(directory)
            with self.assertRaisesRegex(StateError, 'context is missing or invalid'):
                self.call()
        self.assertEqual((self.credentials.calls, self.transport.calls), (0, 0))

    def test_bad_target_and_cost_fail_before_credentials(self):
        self.adapter.policy = OpenAIProviderPolicy(live_enabled=True)
        for model, cost in [('other', Decimal('0.25')), ('gpt-5.6-sol', Decimal('1'))]:
            with self.subTest(model=model, cost=cost), self.assertRaises((OpenAIProviderPricingError, OpenAIProviderProtocolError)):
                self.adapter.generate(input_bytes=b'data', model_id=model, maximum_cost_usd=cost)
        self.assertEqual((self.credentials.calls, self.transport.calls), (0, 0))

    def test_malformed_completions_fail_closed(self):
        self.adapter.policy = OpenAIProviderPolicy(live_enabled=True)
        for payload in (response(model='wrong'), response(output_type='function_call'),
                        response(output_tokens=4097),
                        {**response(), 'status': 'incomplete'},
                        {**response(), 'output': [{'type': 'message', 'role': 'assistant',
                            'content': [{'type': 'refusal', 'refusal': 'no'}]}]}):
            self.transport.payload = payload
            with self.subTest(payload=payload), self.assertRaises(OpenAIProviderProtocolError):
                self.call()

    def test_http_failure_reports_only_status_without_retry(self):
        self.adapter.policy = OpenAIProviderPolicy(live_enabled=True)
        self.transport.payload = {'error': {'message': 'private-upstream-data'}}
        for status in (400, 401, 403, 404, 429, 500, 503):
            with self.subTest(status=status):
                self.transport.status_code = status
                before = self.transport.calls
                with self.assertRaises(OpenAIProviderProtocolError) as caught:
                    self.call()
                self.assertEqual(str(caught.exception),
                    f'acceptance provider returned HTTP {status}; do not retry')
                self.assertEqual(self.transport.calls, before + 1)

    def test_malformed_http_status_is_not_logged_or_accepted(self):
        self.adapter.policy = OpenAIProviderPolicy(live_enabled=True)
        for status in (200.0, True, 99, 600, 'private-upstream-data'):
            with self.subTest(status=status):
                self.transport.status_code = status
                before = self.transport.calls
                with self.assertRaises(OpenAIProviderProtocolError) as caught:
                    self.call()
                self.assertEqual(str(caught.exception),
                    'acceptance provider HTTP response is invalid')
                self.assertEqual(self.transport.calls, before + 1)


if __name__ == '__main__':
    unittest.main()
