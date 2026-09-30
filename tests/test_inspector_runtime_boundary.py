import base64
import sys
import unittest
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / 'src'), str(ROOT / 'scripts')]

from factory_runtime.lambda_role import handle_inspector_runtime_boundary_probe
from factory_state.model import StateError
from prepare_role_transport_canary import verify_inspector_runtime_boundary

NOW = datetime(2026, 9, 29, 11, 0, tzinfo=timezone.utc)
COMMIT = 'a' * 40
NONCE = 'inspector-runtime-1234'


class Signer:
    identity = 'independent_inspector_service'

    def sign(self, payload, *, now):
        return b's' * 64


class Verifier:
    def __init__(self):
        self.calls = []

    def _verify(self, payload, signature, identity, now):
        self.calls.append((payload, signature, identity, now))


class InspectorRuntimeBoundaryTests(unittest.TestCase):
    def event(self):
        return {'kind': 'inspector_runtime_boundary_probe',
                'source_commit': COMMIT, 'nonce': NONCE,
                'task_id': 'deterministic-text-fingerprint'}

    def test_model_free_probe_composes_exact_runtime_and_signs_boundary(self):
        proof = handle_inspector_runtime_boundary_probe(
            self.event(), role='inspector', commit=COMMIT,
            signer=Signer(), now=NOW, root=ROOT)
        self.assertEqual(proof['model_calls'], 0)
        self.assertFalse(proof['operational_execution_enabled'])
        payload = proof['payload']
        self.assertEqual(payload['model_id'], 'global.anthropic.claude-sonnet-5-5')
        self.assertEqual(payload['maximum_cost_usd_per_call'], '0.25')
        self.assertEqual(payload['reserved_cost_usd'], '0.24096')
        self.assertEqual(payload['maximum_provider_calls'], 1)
        self.assertEqual(payload['maximum_request_bytes'], 42020)
        self.assertTrue(payload['reviewer_publication_requires_authenticated_decision'])
        self.assertFalse(payload['operational_execution_enabled'])

        verifier = Verifier()
        checked = verify_inspector_runtime_boundary(
            proof, commit=COMMIT, nonce=NONCE,
            verifier=verifier, now=NOW)
        self.assertEqual(checked, payload)
        self.assertEqual(verifier.calls[0][1], b's' * 64)
        self.assertEqual(verifier.calls[0][2], 'independent_inspector_service')

    def test_wrong_role_or_changed_binding_fails_closed(self):
        with self.assertRaisesRegex(StateError, 'invalid Inspector'):
            handle_inspector_runtime_boundary_probe(
                self.event(), role='builder', commit=COMMIT,
                signer=Signer(), now=NOW, root=ROOT)

        proof = handle_inspector_runtime_boundary_probe(
            self.event(), role='inspector', commit=COMMIT,
            signer=Signer(), now=NOW, root=ROOT)
        proof['payload']['model_id'] = 'other-model'
        with self.assertRaisesRegex(RuntimeError, 'binding mismatch'):
            verify_inspector_runtime_boundary(
                proof, commit=COMMIT, nonce=NONCE,
                verifier=Verifier(), now=NOW)


if __name__ == '__main__':
    unittest.main()
