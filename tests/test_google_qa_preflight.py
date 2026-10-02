import copy
import json
import sys
import unittest
import urllib.error
from pathlib import Path
from unittest.mock import Mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))
from factory_runtime.google_qa import MODEL, request_body
from factory_runtime.google_qa_preflight import (
    MODEL_URL, COUNT_URL, build, validate_model, validate_count, PreflightTransport)
from factory_runtime.review_preparation import prepare
from factory_state.model import StateError


class PreflightTests(unittest.TestCase):
    def setUp(self):
        self.model = {'name': 'models/' + MODEL, 'inputTokenLimit': 32768,
                      'outputTokenLimit': 4096, 'supportedGenerationMethods': ['generateContent']}

    def response(self, value):
        response = Mock(status=200)
        response.read.return_value = json.dumps(value).encode()
        manager = Mock()
        manager.__enter__ = Mock(return_value=response)
        manager.__exit__ = Mock(return_value=False)
        return manager

    def test_count_contains_entire_exact_generation_request(self):
        plan = build(ROOT)
        body = copy.deepcopy(plan['count_request']['generateContentRequest'])
        self.assertEqual(body.pop('model'), 'models/' + MODEL)
        self.assertEqual(body, json.loads(request_body(prepare(ROOT, role='qa'), root=ROOT)))
        self.assertTrue(plan['approval_required'])
        self.assertEqual(plan['generation_calls'], 0)

    def test_only_metadata_and_count_endpoints_once(self):
        opener = Mock()
        opener.open.side_effect = [self.response(self.model), self.response({'totalTokens': 2345})]
        transport = PreflightTransport(opener=opener)
        result = transport.run_once(root=ROOT, api_key='test-key-not-a-real-key')
        self.assertEqual(result['input_tokens'], 2345)
        self.assertFalse(result['output_thinking_cap_qualified'])
        self.assertFalse(result['budget_reserved'])
        requests = [call.args[0] for call in opener.open.call_args_list]
        self.assertEqual([(r.full_url, r.method) for r in requests], [(MODEL_URL, 'GET'), (COUNT_URL, 'POST')])
        self.assertNotIn('test-key', requests[0].full_url)
        with self.assertRaises(StateError):
            transport.run_once(root=ROOT, api_key='test-key-not-a-real-key')
        self.assertEqual(opener.open.call_count, 2)

    def test_wrong_metadata_prevents_source_transmission(self):
        for change in ({'name': 'models/other'}, {'inputTokenLimit': True},
                       {'outputTokenLimit': 4095}, {'supportedGenerationMethods': []}):
            opener = Mock()
            opener.open.return_value = self.response({**self.model, **change})
            with self.assertRaises(StateError):
                PreflightTransport(opener=opener).run_once(root=ROOT, api_key='test-key-not-a-real-key')
            self.assertEqual(opener.open.call_count, 1)

    def test_uncertain_failure_consumes_attempt_and_redacts(self):
        opener = Mock()
        opener.open.side_effect = urllib.error.URLError('PRIVATE_CREDENTIAL')
        transport = PreflightTransport(opener=opener)
        for _ in range(2):
            with self.assertRaises(StateError) as error:
                transport.run_once(root=ROOT, api_key='test-key-not-a-real-key')
            self.assertNotIn('PRIVATE', str(error.exception))
        self.assertEqual(opener.open.call_count, 1)

    def test_invalid_counts_and_ambiguous_json_are_rejected(self):
        for value in (True, -1, 0, 32769, '1', None):
            with self.assertRaises(StateError): validate_count(json.dumps({'totalTokens': value}).encode())
        for raw in (b'{"totalTokens":1,"totalTokens":2}', b'[]', b'null', b'\xff', b'x'*65537,
                    b'{"totalTokens":1,"cachedContentTokenCount":1}'):
            with self.assertRaises(StateError): validate_count(raw)
        with self.assertRaises(StateError): validate_model(b'{"name":')


if __name__ == '__main__':
    unittest.main()
