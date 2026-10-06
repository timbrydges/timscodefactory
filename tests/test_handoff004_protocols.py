import json
import unittest
from pathlib import Path
from factory_runtime import handoff004_packets as packets, handoff004_protocols as protocol
from factory_runtime.pilot002_protocols import request_bytes as old_request
from factory_state.scope import canonical
from factory_state.model import StateError

ROOT = Path(__file__).resolve().parents[1]


class HandoffProtocolTests(unittest.TestCase):
    def setUp(self):
        packet = packets.builder_packet(ROOT)
        self.raw = canonical({'task_id': packets.TASK, 'packet_digest': packet['packet_digest'],
            'files': packet['untrusted_files']})

    def context(self, role):
        return {'role': role, **({} if role == 'builder' else
            {'builder_response': self.raw, 'candidate_commit': 'a'*40})}

    def response(self, role):
        if role == 'builder':
            return {'model': 'gpt-5.6-sol', 'status': 'completed', 'service_tier': 'default',
                'output': [{'type': 'message', 'role': 'assistant', 'status': 'completed',
                    'content': [{'type': 'output_text', 'text': self.raw.decode()}]}],
                'usage': {'input_tokens': 100, 'output_tokens': 30, 'total_tokens': 130,
                    'input_tokens_details': {'cached_tokens': 0},
                    'output_tokens_details': {'reasoning_tokens': 0}}}
        packet = packets.review_packet(ROOT, **self.context(role))
        text = canonical({**{key: packet[key] for key in packets.REVIEW_BINDINGS},
            'verdict': 'ACCEPTED', 'rationale': 'Exact candidate review', 'findings': []}).decode()
        if role == 'inspector':
            return {'stopReason': 'end_turn', 'output': {'message': {'role': 'assistant', 'content': [{'text': text}]}},
                'usage': {'inputTokens': 100, 'outputTokens': 30, 'totalTokens': 130}}
        return {'modelVersion': 'gemini-3.7-flash', 'candidates': [{'finishReason': 'STOP',
            'content': {'role': 'model', 'parts': [{'text': text}]}}],
            'usageMetadata': {'promptTokenCount': 100, 'candidatesTokenCount': 20,
                'thoughtsTokenCount': 10, 'totalTokenCount': 130, 'serviceTier': 'standard'}}

    def test_requests_and_outputs_bind_fresh_task_without_authority(self):
        for role in ('builder', 'inspector', 'qa'):
            with self.subTest(role=role):
                raw = protocol.request_bytes(ROOT, **self.context(role))
                self.assertIn(packets.TASK.encode(), raw)
                self.assertLessEqual(len(raw), 65536)
                result = protocol.parse_response(canonical(self.response(role)), ROOT, **self.context(role))
                self.assertEqual(result['usage']['total_tokens'], 130)
                self.assertFalse(result['provider_identity_verified'])
                self.assertFalse(result['gate_authority'])
        self.assertNotEqual(protocol.request_bytes(ROOT, role='builder'), old_request(ROOT, role='builder'))

    def test_wrong_model_and_paid_tier_rejected(self):
        response = self.response('qa')
        response['modelVersion'] = 'gemini-3.8-flash'
        with self.assertRaises(StateError): protocol.parse_response(canonical(response), ROOT, **self.context('qa'))
        response = self.response('qa')
        response['usageMetadata']['serviceTier'] = 'priority'
        with self.assertRaises(StateError): protocol.parse_response(canonical(response), ROOT, **self.context('qa'))

    def test_task_output_tampering_is_rejected(self):
        response = self.response('builder')
        output = json.loads(self.raw)
        output['task_id'] = 'safe-workspace-fingerprint-001'
        response['output'][0]['content'][0]['text'] = canonical(output).decode()
        with self.assertRaises(StateError): protocol.parse_response(canonical(response), ROOT, role='builder')
