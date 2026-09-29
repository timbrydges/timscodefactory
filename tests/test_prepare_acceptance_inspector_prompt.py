import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / 'scripts'), str(ROOT / 'src'), str(ROOT / 'tests')]

from factory_state.model import StateError
from prepare_acceptance_inspector_prompt import render
from prepare_acceptance_inspector_review import build_packet
from test_acceptance_jobs import NOW
from test_prepare_acceptance_job import fixtures


class InspectorPromptTests(unittest.TestCase):
    def packet(self):
        binding, plan, _, input_bytes, contract_bytes = fixtures()
        return build_packet(binding, plan, input_bytes, contract_bytes, now=NOW)

    def test_request_contains_exact_untrusted_material_without_authority(self):
        packet = self.packet()
        request = render(packet)
        material = json.loads(request['user'])
        self.assertEqual(request['status'], 'PREPARED_NOT_INVOKED')
        self.assertEqual(request['model_calls_authorized'], 0)
        self.assertEqual(request['plan_digest'], packet['plan_digest'])
        self.assertEqual(material['plan_digest'], packet['plan_digest'])
        self.assertEqual(material['input_digest'], packet['input_digest'])
        self.assertNotIn('verdict', material['review_request'])
        self.assertNotIn('rationale', material['review_request'])
        self.assertNotIn('signature', request)
        self.assertNotIn('receipt_versions', request)

    def test_tampering_and_preselected_approval_fail_closed(self):
        packet = self.packet()
        for change in (
                {'review_verdict': 'ACCEPTED'},
                {'model_calls_authorized': 1},
                {'input_digest': '0' * 64},
                {'untrusted_material': {'input_base64': '!',
                                         'contract_base64': packet['untrusted_material']['contract_base64']}},
                {'review_request': {**packet['review_request'], 'verdict': 'ACCEPTED'}}):
            with self.subTest(change=change), self.assertRaises(StateError):
                render({**packet, **change})


if __name__ == '__main__':
    unittest.main()
