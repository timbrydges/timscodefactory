"""Real Ed25519 interoperability with a simulated KMS boundary; no live AWS claim."""
import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / 'src'))
from scripts.scope_dispatch_canary import fixture_keys, sign
from scripts.kms_signing_canary import AwsError, run
from factory_state.kms_signer import ALGORITHM, SIGNERS, KmsReceiptSigner
from factory_state.signers import public_key_der
from factory_state.model import StateError
from test_dispatch_ledger import NOW


class KmsSignerTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.keys, self.private = fixture_keys(self.directory.name, tuple(SIGNERS.values()))
        self.arn = 'arn:aws:kms:ca-central-1:666730517561:key/12345678-1234-1234-1234-123456789abc'
        self.role = 'builder'
        self.sign_calls = []
        self.caller = {'Account': '666730517561',
            'Arn': 'arn:aws:sts::666730517561:assumed-role/tims-factory-signing-builder/test'}
        self.payload = {'kind': 'role_result', 'producer_identity': SIGNERS['builder'],
            'issued_at': int(NOW.timestamp()), 'expires_at': int(NOW.timestamp()) + 60}

    def get_caller_identity(self):
        return self.caller

    def get_public_key(self, *, KeyId):
        return {'KeyId': self.arn, 'KeySpec': 'ECC_NIST_EDWARDS25519',
            'KeyUsage': 'SIGN_VERIFY', 'SigningAlgorithms': [ALGORITHM],
            'PublicKey': public_key_der(self.keys[SIGNERS[self.role]])}

    def sign(self, **request):
        self.sign_calls.append(request)
        if request['KeyId'] != self.arn:
            raise AwsError('AccessDeniedException')
        return {'KeyId': self.arn, 'SigningAlgorithm': ALGORITHM,
            'Signature': sign(json.loads(request['Message']), self.private[SIGNERS[self.role]], self.directory.name)}

    def adapter(self, **patch):
        args = {'signer': self.role, 'key_arn': self.arn,
            'expected_fingerprint': 'sha256:' + hashlib.sha256(public_key_der(self.keys[SIGNERS[self.role]])).hexdigest()}
        return KmsReceiptSigner(self, self, **{**args, **patch})

    def test_kms_raw_signature_verifies_with_existing_ed25519_path(self):
        signature = self.adapter().sign(self.payload, now=NOW)
        self.assertEqual(len(signature), 64)
        self.assertEqual(self.sign_calls[0]['MessageType'], 'RAW')
        self.assertEqual(json.loads(self.sign_calls[0]['Message']), self.payload)

    def test_alias_fingerprint_and_authenticated_role_mismatch_fail(self):
        for patch in ({'key_arn': 'alias/tims-factory-signing-builder'},
                      {'expected_fingerprint': 'sha256:' + '0' * 64}, {'signer': 'inspector'}):
            with self.assertRaises(StateError): self.adapter(**patch)
        self.assertEqual(self.sign_calls, [])

    def test_role_cannot_sign_owner_or_reviewer_receipts(self):
        adapter = self.adapter()
        for patch in ({'kind': 'capability', 'owner_identity': 'tim_brydges'},
                      {'kind': 'scope_review', 'reviewer_identity': SIGNERS['inspector']},
                      {'producer_identity': SIGNERS['inspector']},
                      {'expires_at': int(NOW.timestamp())}, {'details': 'x' * 4096}):
            with self.assertRaises(StateError): adapter.sign({**self.payload, **patch}, now=NOW)
        self.assertEqual(self.sign_calls, [])

    def test_role_is_rechecked_at_sign_time(self):
        adapter = self.adapter()
        self.caller['Arn'] = self.caller['Arn'].replace('builder', 'inspector')
        with self.assertRaises(StateError): adapter.sign(self.payload, now=NOW)
        self.assertEqual(self.sign_calls, [])

    def test_challenge_canary_denies_three_other_keys_and_emits_candidate_only(self):
        result = run('builder', '456-1', 'b' * 40, kms=self, sts=self, now=NOW)
        self.assertEqual(set(result['cross_role_signing_denied']), {'owner', 'planner', 'inspector'})
        self.assertEqual(result['approval_receipts_created'], 0)
        self.assertEqual(result['enrollment_status'], 'CANDIDATE_REQUIRES_REVIEW')
        self.assertNotIn('private_key', json.dumps(result))

    def test_unexpected_cross_role_error_is_not_counted_as_denial(self):
        original = self.sign
        def fail(**request):
            if request['KeyId'] != self.arn:
                raise AwsError('NotFoundException')
            return original(**request)
        self.sign = fail
        with self.assertRaises(AwsError):
            run('builder', '456-1', 'b' * 40, kms=self, sts=self, now=NOW)


class SigningInfrastructureTests(unittest.TestCase):
    def test_roles_have_only_their_own_key_and_no_state_or_provider_permissions(self):
        resources = json.loads((ROOT / 'infra/signing/keys.cloudformation.json').read_text())['Resources']
        self.assertEqual(len(resources), 12)
        for role in SIGNERS:
            name = role.title()
            props = resources[name + 'Role']['Properties']
            trust = props['AssumeRolePolicyDocument']['Statement'][0]['Condition']['StringEquals']
            self.assertEqual(trust['token.actions.githubusercontent.com:workflow'], f'factory-{role}-signing')
            self.assertEqual(trust['token.actions.githubusercontent.com:actor_id'], '214414801')
            self.assertEqual(trust['token.actions.githubusercontent.com:ref'], 'refs/heads/main')
            statements = props['Policies'][0]['PolicyDocument']['Statement']
            self.assertEqual({a for s in statements for a in s['Action']}, {'kms:GetPublicKey', 'kms:Sign'})
            self.assertTrue(all(s['Resource'] == {'Fn::GetAtt': [name + 'Key', 'Arn']} for s in statements))
            deny = resources[name + 'Key']['Properties']['KeyPolicy']['Statement'][1]
            self.assertEqual(deny['Effect'], 'Deny')
            self.assertEqual(deny['Condition']['ArnNotEquals']['aws:PrincipalArn'],
                f'arn:aws:iam::666730517561:role/tims-factory-signing-{role}')

    def test_workflows_are_manual_disabled_and_bound_to_their_role(self):
        for role in SIGNERS:
            workflow = (ROOT / f'.github/workflows/factory-{role}-signing.yml').read_text()
            self.assertIn("vars.FACTORY_SIGNING_CANARY_ENABLED == 'true'", workflow)
            self.assertIn(f'role/tims-factory-signing-{role}', workflow)
            self.assertNotIn('schedule:', workflow)
            self.assertNotIn('pull_request:', workflow)
            self.assertNotIn('push:', workflow)
