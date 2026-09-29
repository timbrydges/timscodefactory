import base64
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / 'scripts'), str(ROOT / 'src'), str(ROOT / 'tests')]

from factory_state.model import StateError
from prepare_acceptance_inspector_review import build_packet
from test_acceptance_jobs import NOW
from test_prepare_acceptance_job import fixtures


class InspectorPacketTests(unittest.TestCase):
    def test_exact_material_has_no_approval_or_spending_authority(self):
        binding, plan, _, input_bytes, contract_bytes = fixtures()
        packet = build_packet(binding, plan, input_bytes, contract_bytes, now=NOW)
        self.assertEqual(packet['status'], 'AWAITING_INDEPENDENT_AI_INSPECTION')
        self.assertEqual(packet['inspector_identity'], 'independent_inspector_service')
        self.assertEqual(packet['required_provider_profile'], 'review_adversarial')
        self.assertEqual(packet['plan_digest'], plan['plan_digest'])
        self.assertNotIn('proposed_review', packet)
        self.assertNotIn('verdict', packet['review_request'])
        self.assertNotIn('rationale', packet['review_request'])
        self.assertEqual(packet['review_request']['binding'], plan['review_payload']['binding'])
        self.assertEqual(base64.b64decode(packet['untrusted_material']['input_base64']), input_bytes)
        self.assertEqual(base64.b64decode(packet['untrusted_material']['contract_base64']), contract_bytes)
        self.assertIsNone(packet['review_verdict'])
        self.assertIsNone(packet['signature'])
        self.assertIsNone(packet['receipt_versions'])
        self.assertEqual(packet['model_calls_authorized'], 0)

    def test_changed_or_expired_material_is_rejected_before_packet(self):
        binding, plan, _, input_bytes, contract_bytes = fixtures()
        with self.assertRaises(StateError):
            build_packet(binding, plan, input_bytes + b'changed', contract_bytes, now=NOW)
        with self.assertRaises(StateError):
            build_packet(binding, plan, input_bytes, contract_bytes,
                         now=NOW.replace(hour=8))


if __name__ == '__main__':
    unittest.main()
