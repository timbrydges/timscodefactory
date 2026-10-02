import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))
from factory_runtime.review_preparation import (
    BINDING, BOOTSTRAP, PACKET, REVIEW, digest, prepare, parse_assessment, validate_packet,
)
from factory_state.model import StateError


class ReviewPreparationTests(unittest.TestCase):
    def response(self, packet):
        return {**{k: packet[k] for k in BINDING}, 'verdict': 'ACCEPTED',
                'rationale': 'Inspected exact candidate', 'findings': []}

    def test_role_specific_packets_do_not_confer_authority(self):
        qa, security = (prepare(ROOT, role=r) for r in ('qa', 'security'))
        self.assertNotEqual(qa['packet_digest'], security['packet_digest'])
        self.assertNotEqual(qa['verified_identity_fingerprint'], security['verified_identity_fingerprint'])
        self.assertEqual(security['required_state'], 'SECURITY_REVIEW')
        for packet in (qa, security):
            validate_packet(packet, root=ROOT)
            result = parse_assessment(json.dumps(self.response(packet)).encode(), packet, root=ROOT)
            self.assertEqual(result['status'], 'UNAUTHENTICATED_ASSESSMENT')
            self.assertFalse(result['gate_authority'])
            self.assertEqual(packet['model_calls_authorized'], 0)

    def test_rehashed_candidate_or_permission_changes_fail(self):
        for key, value in [('candidate_commit', 'a'*40), ('model_calls_authorized', 1),
                           ('model_calls_authorized', False), ('prerequisite', 'none'),
                           ('identity_is_operationally_enrolled', True)]:
            packet = prepare(ROOT, role='qa')
            packet[key] = value
            packet.pop('packet_digest')
            packet['packet_digest'] = digest(packet)
            with self.subTest(key=key), self.assertRaises(StateError):
                validate_packet(packet, root=ROOT)

    def test_pinned_artifacts_reject_tampering(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for path in (PACKET, REVIEW, BOOTSTRAP):
                target = root / path
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes((ROOT/path).read_bytes())
            for path in (PACKET, REVIEW, BOOTSTRAP):
                target = root / path
                original = target.read_bytes()
                target.write_bytes(original+b' ')
                with self.subTest(path=path), self.assertRaises(StateError):
                    prepare(root, role='qa')
                target.write_bytes(original)

    def test_role_replay_duplicate_and_extra_fields_fail(self):
        packet = prepare(ROOT, role='qa')
        response = self.response(packet)
        wrong = self.response(prepare(ROOT, role='security'))
        for value in (wrong, {**response, 'signature': 'fake'}, {**response, 'findings': [{}]}):
            with self.assertRaises(StateError):
                parse_assessment(json.dumps(value).encode(), packet, root=ROOT)
        raw = json.dumps(response)[:-1] + ',"verdict":"REJECTED"}'
        with self.assertRaises(StateError):
            parse_assessment(raw.encode(), packet, root=ROOT)

    def test_critical_findings_cannot_be_accepted(self):
        packet = prepare(ROOT, role='security')
        response = self.response(packet)
        response['findings'] = [{'severity': 'critical', 'path': 'fingerprint.py', 'detail': 'Example defect'}]
        with self.assertRaises(StateError):
            parse_assessment(json.dumps(response).encode(), packet, root=ROOT)
        response['verdict'] = 'REJECTED'
        self.assertFalse(parse_assessment(json.dumps(response).encode(), packet, root=ROOT)['gate_authority'])

    def test_malformed_and_oversized_model_output_fails(self):
        packet = prepare(ROOT, role='qa')
        for raw in (b'', b'\xff', b'[]', b'x'*16385):
            with self.assertRaises(StateError):
                parse_assessment(raw, packet, root=ROOT)

    def test_invalid_roles_and_unbounded_findings_fail(self):
        for role in (None, [], 'builder'):
            with self.assertRaises(StateError):
                prepare(ROOT, role=role)
            with self.assertRaises(StateError):
                validate_packet({'role': role}, root=ROOT)
        packet = prepare(ROOT, role='qa')
        finding = {'severity': 'low', 'path': 'fingerprint.py', 'detail': 'Example'}
        for update in ({'findings': [finding]*17}, {'rationale': 'x'*2001},
                       {'findings': [{**finding, 'path': '../secret'}]},
                       {'findings': [{**finding, 'detail': 'x'*1001}]}):
            with self.assertRaises(StateError):
                parse_assessment(json.dumps({**self.response(packet), **update}).encode(), packet, root=ROOT)


if __name__ == '__main__':
    unittest.main()
