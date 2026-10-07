from dataclasses import replace
import json
import unittest
from factory_runtime.security_provider_protocol import job_input, prepare, parse_response
from factory_runtime.worker import digest
from factory_runtime.security_policy import policy_bytes, policy_digest
from factory_state.model import StateError
from factory_state.scope import canonical
from test_security_provider_scope import fixture


class SecurityProtocolTests(unittest.TestCase):
    def setUp(self):
        scope, _, _, _ = fixture()
        self.files = {'fingerprint.py': 'print("fixture")\n', 'tests/test_fingerprint.py': '# fixture\n'}
        binding = replace(scope.binding, qa=replace(scope.binding.qa,
            candidate_digest=digest(canonical(self.files)), allowed_paths=tuple(self.files)))
        self.raw = job_input(binding, self.files)
        binding = replace(binding, input_digest=digest(self.raw))
        request = replace(scope.request, input_digest=digest(self.raw))
        self.prepared = prepare(binding=binding, request=request, files=self.files, input_bytes=self.raw)
        self.output = {**json.loads(self.prepared.expected_output), 'verdict': 'ACCEPTED',
                       'rationale': 'Fixture only.', 'findings': []}

    def response(self, **changes):
        return canonical({'stopReason': 'end_turn',
            'output': {'message': {'role': 'assistant', 'content': [{'text': canonical(self.output).decode()}]}},
            'usage': {'inputTokens': 100, 'outputTokens': 50, 'totalTokens': 150}, **changes})

    def test_exact_request_and_text_response(self):
        self.prepared.validate()
        body = json.loads(self.prepared.scope.request_bytes)
        self.assertEqual(body['inferenceConfig']['maxTokens'], 4096)
        self.assertNotIn('toolConfig', body)
        output, usage = parse_response(self.response(), self.prepared)
        self.assertEqual(json.loads(output), self.output)
        self.assertEqual(usage['input_tokens'], 100)

    def test_policy_material_is_in_job_and_wire_without_receipt_cycle(self):
        job = json.loads(self.raw)
        body = json.loads(self.prepared.scope.request_bytes)
        packet = json.loads(body['messages'][0]['content'][0]['text'])
        self.assertEqual(job['security_policy'], json.loads(policy_bytes()))
        self.assertEqual(packet['security_policy'], job['security_policy'])
        self.assertEqual(job['security_scope_digest'], policy_digest())
        self.assertNotIn('input_digest', job['security_policy'])
        self.assertFalse(job['security_policy']['risk_waivers_allowed'])
        bad = replace(self.prepared.scope.binding, security_scope_digest=digest(b'changed policy'))
        with self.assertRaises(StateError): job_input(bad, self.files)
        job['security_policy']['risk_waivers_allowed'] = True
        with self.assertRaises(StateError):
            prepare(binding=self.prepared.scope.binding, request=self.prepared.scope.request,
                    files=self.files, input_bytes=canonical(job))

    def test_rejected_findings_retained_without_gate_authority(self):
        self.output.update(verdict='REJECTED', findings=[{'severity':'critical',
            'path':'fingerprint.py', 'detail':'Fixture risk'}])
        output, _ = parse_response(self.response(), self.prepared)
        self.assertEqual(json.loads(output), self.output)

    def test_source_and_wire_tampering_rejected(self):
        with self.assertRaises(StateError):
            prepare(binding=self.prepared.scope.binding, request=self.prepared.scope.request,
                files={**self.files, 'fingerprint.py':'changed'}, input_bytes=self.raw)
        with self.assertRaises(StateError):
            replace(self.prepared, scope=replace(self.prepared.scope, request_bytes=b'changed')).validate()

    def test_unsafe_envelopes_and_usage_rejected(self):
        for change in ({'stopReason':'max_tokens'}, {'stopReason':'tool_use'},
                {'usage':{'inputTokens':True,'outputTokens':50,'totalTokens':51}},
                {'usage':{'inputTokens':100,'outputTokens':50,'totalTokens':150,'cacheReadInputTokens':1}},
                {'serviceTier':{'type':'priority'}}):
            with self.assertRaises(StateError): parse_response(self.response(**change), self.prepared)

    def test_changed_provenance_or_extra_authority_and_malformed_output_rejected(self):
        original = dict(self.output)
        for change in ({'qa_result_digest':digest(b'other')}, {'security_scope_digest':digest(b'other')},
                {'production_release_authorized':True}, {'findings':[{'severity':'low','path':[], 'detail':'x'}]}):
            self.output = {**original, **change}
            with self.assertRaises(StateError): parse_response(self.response(), self.prepared)
        for raw in (b'[]', b'\xff', b'{"x":NaN}'):
            with self.assertRaises(StateError): parse_response(raw, self.prepared)


if __name__ == '__main__': unittest.main()
