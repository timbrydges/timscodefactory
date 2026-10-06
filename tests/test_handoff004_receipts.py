import base64
import copy
import unittest
from datetime import datetime, timezone
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from factory_runtime import handoff004_packets as packets
from factory_runtime.handoff004_receipts import IDENTITIES, sha, verify_chain, verify_predecessors
from factory_state.model import StateError
from factory_state.scope import canonical

ROOT = Path(__file__).resolve().parents[1]


class HandoffReceiptTests(unittest.TestCase):
    def setUp(self):
        self.private = {role: Ed25519PrivateKey.generate() for role in IDENTITIES}
        self.keys = {identity: self.private[role].public_key().public_bytes(
            Encoding.PEM, PublicFormat.SubjectPublicKeyInfo) for role, identity in IDENTITIES.items()}
        self.now = datetime(2026, 10, 6, tzinfo=timezone.utc)
        self.requests = {role: sha(role.encode()) for role in IDENTITIES}
        packet = packets.builder_packet(ROOT)
        self.builder = canonical({'task_id': packets.TASK, 'packet_digest': packet['packet_digest'],
                                  'files': packet['untrusted_files']})
        models = {p['role']: p['model_id'] for p in packets.facts(ROOT)[0]['providers']}
        self.chain = {}
        previous = None
        for role, identity in IDENTITIES.items():
            output = self.builder
            if role != 'builder':
                packet = packets.review_packet(ROOT, role=role, builder_response=self.builder,
                                               candidate_commit='b' * 40)
                output = canonical({**{key: packet[key] for key in packets.REVIEW_BINDINGS},
                    'verdict': 'ACCEPTED', 'rationale': 'Reviewed exact candidate', 'findings': []})
            payload = {'kind': 'handoff004_role_result', 'task_id': packets.TASK,
                'role': role, 'producer_identity': identity, 'model_id': models[role],
                'source_commit': 'a' * 40, 'contract_digest': 'sha256:' + packets.PINNED[packets.CONTRACT],
                'request_digest': self.requests[role], 'output_digest': sha(output),
                'predecessor_receipt_digest': previous, 'transport_invocations': 1,
                'issued_at': int(self.now.timestamp()) - 1, 'expires_at': int(self.now.timestamp()) + 60,
                'actual_micro_usd': 100000, 'provider_response_digest': sha(b'provider response')}
            self.chain[role] = {'payload': payload, 'output_base64': base64.b64encode(output).decode()}
            self.sign(role)
            previous = sha(canonical(payload))

    def sign(self, role):
        self.chain[role]['signature_base64'] = base64.b64encode(
            self.private[role].sign(canonical(self.chain[role]['payload']))).decode()

    def verify(self, **kwargs):
        args = dict(root=ROOT, trusted_keys=self.keys, source_commit='a' * 40,
            candidate_commit='b' * 40, request_digests=self.requests, now=self.now,
            verify_executed_tests=lambda commit, digest: commit == 'b' * 40 and
                digest == packets.parse_builder(self.builder, root=ROOT)['candidate_digest'])
        return verify_chain(self.chain, **{**args, **kwargs})

    def test_real_three_key_chain_and_exact_test_binding(self):
        result = self.verify()
        self.assertEqual(result['status'], 'AUTHENTICATED_HANDOFF_VERIFIED')
        self.assertEqual(result['reported_actual_micro_usd'], 300000)
        self.assertFalse(result['gate_authority'])

    def test_prefix_authentication_before_next_attempt(self):
        for next_role, roles in (('inspector', ('builder',)), ('qa', ('builder', 'inspector'))):
            context = dict(next_role=next_role, root=ROOT, trusted_keys=self.keys,
                source_commit='a'*40, candidate_commit='b'*40, now=self.now,
                request_digests={role: self.requests[role] for role in roles})
            prefix = {role: self.chain[role] for role in roles}
            verified = verify_predecessors(prefix, **context)
            self.assertEqual(verified['builder_response'], self.builder)
            self.assertEqual(verified['predecessor_receipt_digest'], sha(canonical(self.chain[roles[-1]]['payload'])))
            with self.assertRaises(StateError): verify_predecessors({}, **context)
            with self.assertRaises(StateError): verify_predecessors(self.chain, **context)

    def test_signed_but_wrong_bindings_or_cost_rejected(self):
        original = copy.deepcopy(self.chain)
        for field, value in [('actual_micro_usd', 250001), ('actual_micro_usd', True),
            ('transport_invocations', True), ('predecessor_receipt_digest', sha(b'wrong')),
            ('source_commit', 'c' * 40), ('request_digest', sha(b'wrong')),
            ('kind', 'handoff001_role_result'), ('task_id', 'authenticated-handoff-001'),
            ('role', 'builder'), ('expires_at', int(self.now.timestamp())),
            ('issued_at', int(self.now.timestamp()) + 1)]:
            with self.subTest(field=field, value=value):
                self.chain = copy.deepcopy(original)
                self.chain['inspector']['payload'][field] = value
                self.sign('inspector')
                with self.assertRaises(StateError): self.verify()

    def test_output_or_signature_tampering_rejected(self):
        self.chain['qa']['output_base64'] = base64.b64encode(b'{}').decode()
        with self.assertRaises(StateError): self.verify()
        self.setUp()
        self.chain['qa']['signature_base64'] = base64.b64encode(bytes(64)).decode()
        with self.assertRaises(StateError): self.verify()

    def test_missing_shared_or_unknown_keys_rejected(self):
        with self.assertRaises(StateError): self.verify(trusted_keys={})
        with self.assertRaises(StateError): self.verify(trusted_keys=dict.fromkeys(self.keys, next(iter(self.keys.values()))))
        wrong = Ed25519PrivateKey.generate().public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
        with self.assertRaises(StateError): self.verify(trusted_keys={**self.keys, IDENTITIES['qa']: wrong})

    def test_real_tests_required_and_errors_redacted(self):
        for value in (False, 1, 'passed', None):
            with self.subTest(value=value), self.assertRaises(StateError):
                self.verify(verify_executed_tests=lambda *_: value)
        def broken(*_):
            raise RuntimeError('sensitive diagnostic')
        with self.assertRaisesRegex(StateError, '^Independent execution verification failed$'):
            self.verify(verify_executed_tests=broken)
        with self.assertRaises(StateError): self.verify(now=self.now.replace(tzinfo=None))

    def test_signed_rejection_never_authorizes_progression(self):
        import json
        envelope = self.chain['qa']
        output = json.loads(base64.b64decode(envelope['output_base64']))
        output['verdict'] = 'REJECTED'
        raw = canonical(output)
        envelope['output_base64'] = base64.b64encode(raw).decode()
        envelope['payload']['output_digest'] = sha(raw)
        self.sign('qa')
        with self.assertRaisesRegex(StateError, 'review rejected'): self.verify()
