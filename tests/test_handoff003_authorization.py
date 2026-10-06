import base64
import copy
from datetime import datetime, timezone
from pathlib import Path
import unittest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from factory_runtime import handoff003_packets as packets, handoff003_protocols as protocols
from factory_runtime.handoff003_authorization import verify
from factory_runtime.handoff003_receipts import sha
from factory_state.scope import canonical
from factory_state.model import OWNER_IDENTITY, StateError

ROOT = Path(__file__).resolve().parents[1]


class HandoffAuthorizationTests(unittest.TestCase):
    def setUp(self):
        self.private = Ed25519PrivateKey.generate()
        self.keys = {OWNER_IDENTITY: self.private.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)}
        self.now = datetime(2026, 10, 6, tzinfo=timezone.utc)
        self.context = {'role': 'builder'}
        self.prepare()

    def prepare(self):
        packet = protocols.packet(ROOT, **self.context)
        self.raw = protocols.request_bytes(ROOT, **self.context)
        self.predecessor = None if self.context['role'] == 'builder' else sha(b'verified predecessor')
        bindings = {key: packet[key] for key in ('role', 'model_id', 'task_id', 'contract_digest', 'packet_digest')}
        bindings.update(source_commit='a'*40, request_digest=sha(self.raw), predecessor_receipt_digest=self.predecessor)
        window = {'issued_at': int(self.now.timestamp())-1, 'expires_at': int(self.now.timestamp())+60}
        self.pricing = {'kind': 'handoff003_qualified_request_cost_bound', **bindings,
            'currency': 'USD', 'complete_request_bound_qualified': True, 'maximum_cost_micro_usd': 240000,
            **window, 'evidence_digest': sha(b'qualified complete request')}
        self.readiness = {'kind': 'handoff003_provider_readiness', **bindings,
            'credential_route_verified': True, 'model_metadata_verified': True,
            'repository_binding_verified': True, 'single_attempt_failure_risk_accepted': True,
            **window, 'evidence_digest': sha(b'observed route')}
        self.payload = {'kind': 'handoff003_exact_request_allowance', 'owner_identity': OWNER_IDENTITY,
            **bindings, 'budget_approval_digest': 'sha256:'+packets.PINNED[packets.APPROVAL],
            'pricing_digest': packets.digest(self.pricing), 'readiness_digest': packets.digest(self.readiness),
            'reserved_micro_usd': 250000, 'approved_cap_micro_usd': 250000,
            'maximum_provider_calls': 1, 'retries': 0, 'task_state_writes': 0,
            'gate_authority': False, 'production_release_authorized': False, **window}

    def verify(self, **changes):
        envelope = {'payload': self.payload, 'signature': base64.b64encode(self.private.sign(canonical(self.payload))).decode()}
        args = dict(root=ROOT, **self.context, request_bytes=self.raw, source_commit='a'*40,
            pricing=self.pricing, readiness=self.readiness, trusted_keys=self.keys, now=self.now,
            predecessor_receipt_digest=self.predecessor)
        return verify(envelope, **{**args, **changes})

    def test_fresh_signed_allowances_for_all_three_roles(self):
        builder = packets.builder_packet(ROOT)
        raw = canonical({'task_id': packets.TASK, 'packet_digest': builder['packet_digest'], 'files': builder['untrusted_files']})
        for role in ('builder', 'inspector', 'qa'):
            self.context = {'role': role, **({} if role == 'builder' else {'builder_response': raw, 'candidate_commit': 'b'*40})}
            self.prepare()
            result = self.verify()
            self.assertEqual(result['role'], role)
            self.assertEqual(result['request_bytes'], self.raw)

    def test_old_scope_or_increased_authority_rejected_even_when_signed(self):
        original = copy.deepcopy(self.payload)
        for field, value in [('kind', 'pilot002_exact_request_allowance'), ('task_id', 'safe-workspace-fingerprint-001'),
            ('retries', 1), ('maximum_provider_calls', 2), ('task_state_writes', 1),
            ('gate_authority', True), ('approved_cap_micro_usd', 250001), ('budget_approval_digest', sha(b'old'))]:
            with self.subTest(field=field):
                self.payload = {**original, field: value}
                with self.assertRaises(StateError): self.verify()

    def test_expiry_changed_request_unqualified_cost_and_bad_signature_rejected(self):
        with self.assertRaises(StateError): self.verify(request_bytes=self.raw+b' ')
        with self.assertRaises(StateError): self.verify(now=datetime(2026, 10, 7, tzinfo=timezone.utc))
        with self.assertRaises(StateError): self.verify(trusted_keys={})
        with self.assertRaises(StateError): self.verify(predecessor_receipt_digest=sha(b'other'))
        self.pricing['maximum_cost_micro_usd'] = 250001
        self.payload['pricing_digest'] = packets.digest(self.pricing)
        with self.assertRaises(StateError): self.verify()

    def test_signed_missing_readiness_does_not_qualify(self):
        self.readiness['credential_route_verified'] = False
        self.payload['readiness_digest'] = packets.digest(self.readiness)
        with self.assertRaises(StateError): self.verify()
