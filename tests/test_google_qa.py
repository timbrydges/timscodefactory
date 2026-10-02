import copy
import json
import sys
import unittest
import urllib.error
from pathlib import Path
from unittest.mock import Mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))
sys.path.insert(0, str(ROOT / 'scripts'))
from prepare_google_qa import build, credential_template
from factory_runtime.google_qa import ENDPOINT, MODEL, GoogleQATransport, NoRedirect, request_body, parse_response
from factory_runtime.review_preparation import BINDING, prepare
from factory_state.model import StateError


class GoogleQATests(unittest.TestCase):
    def setUp(self):
        self.packet = prepare(ROOT, role='qa')
        assessment = {**{k: self.packet[k] for k in BINDING},
                      'verdict': 'ACCEPTED', 'rationale': 'Reviewed source', 'findings': []}
        self.response = {'modelVersion': MODEL, 'candidates': [{'finishReason': 'STOP',
            'content': {'role': 'model', 'parts': [{'text': json.dumps(assessment)}]}}],
            'usageMetadata': {'promptTokenCount': 2000, 'candidatesTokenCount': 500,
                              'thoughtsTokenCount': 100, 'totalTokenCount': 2600}}

    def test_google_only_bounded_request_has_no_tools_or_credentials(self):
        body = json.loads(request_body(self.packet, root=ROOT))
        self.assertEqual(set(body), {'systemInstruction', 'contents', 'generationConfig'})
        self.assertEqual(body['generationConfig']['candidateCount'], 1)
        self.assertEqual(body['generationConfig']['maxOutputTokens'], 4096)
        with self.assertRaises(StateError):
            request_body(prepare(ROOT, role='security'), root=ROOT)

    def test_setup_plan_cannot_create_key_value_or_grant_readers(self):
        plan = build(ROOT)
        self.assertEqual(plan['model_calls_authorized'], 0)
        resources = credential_template()['Resources']
        self.assertEqual(list(resources), ['GoogleQaSecret'])
        props = resources['GoogleQaSecret']['Properties']
        self.assertEqual(set(props), {'Name', 'KmsKeyId', 'Description'})
        self.assertEqual(plan['credential_setup_proposal']['runtime_reader_grants'], [])
        self.assertFalse(plan['credential_setup_proposal']['new_google_billing_link'])

    def test_parsed_usage_counts_thinking_without_granting_authority(self):
        parsed = parse_response(json.dumps(self.response).encode(), self.packet, root=ROOT)
        self.assertEqual(parsed['output_tokens_including_thinking'], 600)
        self.assertFalse(parsed['gate_authority'])
        self.assertFalse(parsed['assessment']['gate_authority'])

    def test_wrong_model_truncation_tools_and_usage_rejected(self):
        cases = []
        for field, value in [('modelVersion', 'openai'), ('promptFeedback', {'blockReason': 'SAFETY'})]:
            cases.append({**self.response, field: value})
        for field, value in [('promptTokenCount', True), ('totalTokenCount', 1),
                             ('thoughtsTokenCount', 4097), ('promptTokenCount', 32769)]:
            cases.append({**self.response, 'usageMetadata': {**self.response['usageMetadata'], field: value}})
        for change in ('MAX_TOKENS', 'functionCall'):
            response = copy.deepcopy(self.response)
            if change == 'MAX_TOKENS': response['candidates'][0]['finishReason'] = change
            else: response['candidates'][0]['content']['parts'] = [{'functionCall': {'name': 'exec'}}]
            cases.append(response)
        for response in cases:
            with self.assertRaises(StateError):
                parse_response(json.dumps(response).encode(), self.packet, root=ROOT)

    def test_duplicate_malformed_and_oversized_responses_rejected(self):
        valid = json.dumps(self.response)
        for raw in (b'[]', b'null', b'\xff', b'x'*65537,
                    (valid[:-1]+',"modelVersion":"'+MODEL+'"}').encode()):
            with self.assertRaises(StateError): parse_response(raw, self.packet, root=ROOT)

    def test_http_failure_consumes_local_attempt_and_redacts_error(self):
        opener = Mock()
        opener.open.side_effect = urllib.error.URLError('PRIVATE_KEY_VALUE')
        transport = GoogleQATransport(opener=opener)
        for _ in range(2):
            with self.assertRaises(StateError) as caught:
                transport.send_once(self.packet, root=ROOT, api_key='test-credential-not-real')
            self.assertNotIn('PRIVATE_KEY_VALUE', str(caught.exception))
        self.assertEqual(opener.open.call_count, 1)
        request = opener.open.call_args.args[0]
        self.assertEqual(request.full_url, ENDPOINT)
        self.assertNotIn('test-credential', request.full_url)
        self.assertEqual(request.get_header('X-goog-api-key'), 'test-credential-not-real')

    def test_invalid_packet_and_key_never_reach_transport(self):
        opener = Mock()
        for packet, key in ((prepare(ROOT, role='security'), 'test-credential-not-real'),
                            (self.packet, 'secret\nheader')):
            with self.assertRaises(StateError):
                GoogleQATransport(opener=opener).send_once(packet, root=ROOT, api_key=key)
        opener.open.assert_not_called()
        with self.assertRaises(StateError):
            NoRedirect().redirect_request(None, None, 302, '', {}, 'https://other.example')


if __name__ == '__main__': unittest.main()
