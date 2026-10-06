import json
import unittest
from pathlib import Path
from factory_runtime import handoff001_packets as packets
from factory_state.model import StateError
from factory_state.scope import canonical

ROOT = Path(__file__).resolve().parents[1]


class HandoffPacketsTests(unittest.TestCase):
    def setUp(self):
        self.packet = packets.builder_packet(ROOT)
        self.response = canonical({'task_id': packets.TASK,
            'packet_digest': self.packet['packet_digest'], 'files': self.packet['untrusted_files']})

    def review(self, role='inspector'):
        packet = packets.review_packet(ROOT, role=role, builder_response=self.response,
                                        candidate_commit='a' * 40)
        value = {key: packet[key] for key in packets.REVIEW_BINDINGS}
        return {**value, 'verdict': 'ACCEPTED', 'rationale': 'Bounded fixture reviewed', 'findings': []}

    def parse(self, value, role='inspector'):
        return packets.parse_review(canonical(value), root=ROOT, role=role,
                                    builder_response=self.response, candidate_commit='a' * 40)

    def test_fresh_identity_and_bounded_budget_preserve_old_pilot(self):
        contract, baseline, approval = packets.facts(ROOT)
        self.assertEqual(contract['task_id'], packets.TASK)
        self.assertEqual(contract['baseline_commit'], baseline['commit'])
        self.assertEqual(approval['approved_total_micro_usd'], 750000)
        self.assertEqual(approval['maximum_attempts_per_provider'], 1)
        self.assertFalse(contract['live_execution_authorized'])
        old = json.loads((ROOT/'factory/autonomy/pilot-002-contract.json').read_text())
        self.assertNotEqual(old['task_id'], contract['task_id'])
        self.assertFalse(packets.parse_builder(self.response, root=ROOT)['gate_authority'])

    def test_both_reviews_remain_untrusted_after_parsing(self):
        for role in ('inspector', 'qa'):
            result = self.parse(self.review(role), role)
            self.assertFalse(result['gate_authority'])
            self.assertFalse(result['tests_executed'])

    def test_old_task_changed_candidate_and_cross_role_rejected(self):
        value = self.review()
        for field in packets.REVIEW_BINDINGS:
            with self.subTest(field=field), self.assertRaises(StateError):
                self.parse({**value, field: 'different'})
        raw = json.loads(self.response)
        raw['task_id'] = 'safe-workspace-fingerprint-001'
        with self.assertRaises(StateError): packets.parse_builder(canonical(raw), root=ROOT)

    def test_blocking_findings_require_rejection(self):
        value = self.review()
        value['findings'] = [{'severity':'high','path':'fingerprint.py','detail':'Unsafe path'}]
        with self.assertRaises(StateError): self.parse(value)
        value['verdict'] = 'REJECTED'
        self.assertEqual(self.parse(value)['verdict'], 'REJECTED')

    def test_duplicate_fields_and_added_authority_rejected(self):
        with self.assertRaises(StateError): packets.parse_builder(b'{"task_id":"x","task_id":"y"}', root=ROOT)
        with self.assertRaises(StateError): self.parse({**self.review(), 'tests_executed': True})

    def test_review_prompt_and_parser_share_output_bounds(self):
        for role in ('inspector', 'qa'):
            packet = packets.review_packet(ROOT, role=role, builder_response=self.response,
                                           candidate_commit='a' * 40)
            for constraint in ('at most 16 entries', '1 to 2000 characters',
                               '1 to 1000 characters', 'tests/test_fingerprint.py'):
                self.assertIn(constraint, packet['instructions'])
            finding = {'severity': 'info', 'path': 'fingerprint.py', 'detail': 'x' * 1000}
            value = {**self.review(role), 'rationale': 'x' * 2000,
                     'findings': [finding] * 16}
            self.assertFalse(self.parse(value, role)['gate_authority'])
            for count in (17, 23):
                with self.subTest(role=role, count=count), self.assertRaises(StateError):
                    self.parse({**value, 'findings': [finding] * count}, role)
            with self.assertRaises(StateError):
                self.parse({**value, 'rationale': 'x' * 2001}, role)
            with self.assertRaises(StateError):
                self.parse({**value, 'findings': [{**finding, 'detail': 'x' * 1001}]}, role)
