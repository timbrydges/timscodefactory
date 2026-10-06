"""Real Ed25519 verification at a simulated isolated KMS boundary."""
import json
import hashlib
import tempfile
import unittest
from unittest.mock import patch

from scripts.scope_dispatch_canary import fixture_keys, sign
from scripts.spec_signing_canary import KEY, IDENTITY, OTHER_ALIASES, ROLE, run
from scripts.kms_signing_canary import AwsError
from factory_state.kms_signer import ALGORITHM
from factory_state.model import StateError
from factory_state.signers import public_key_der
from test_dispatch_ledger import NOW


class SpecCustodyTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.keys, self.private = fixture_keys(self.directory.name, (IDENTITY,))
        self.arn = KEY
        pin = patch('scripts.spec_signing_canary.FINGERPRINT',
                    'sha256:' + hashlib.sha256(public_key_der(self.keys[IDENTITY])).hexdigest())
        pin.start()
        self.addCleanup(pin.stop)
        self.caller = ROLE + 'fixture'
        self.calls = []
        self.bad_signature = False
        self.cross_allowed = False
        self.error_code = 'AccessDeniedException'

    def get_caller_identity(self):
        return {'Account': '666730517561', 'Arn': self.caller}

    def get_public_key(self, **kw):
        self.assertEqual(kw['KeyId'], KEY)
        return {'KeyId': self.arn, 'KeySpec': 'ECC_NIST_EDWARDS25519',
                'KeyUsage': 'SIGN_VERIFY', 'SigningAlgorithms': [ALGORITHM],
                'PublicKey': public_key_der(self.keys[IDENTITY])}

    def sign(self, **kw):
        self.calls.append(kw)
        if kw['KeyId'] != self.arn and not self.cross_allowed:
            raise AwsError(self.error_code)
        signature = sign(json.loads(kw['Message']), self.private[IDENTITY], self.directory.name)
        return {'KeyId': self.arn, 'SigningAlgorithm': ALGORITHM,
                'Signature': b'0' * 64 if self.bad_signature else signature}

    def execute(self, run_id='123-1', now=NOW):
        return run(run_id, 'a' * 40, kms=self, sts=self, now=now)

    def test_verified_custody_is_not_review_authority(self):
        result = self.execute()
        self.assertEqual(result['cross_role_signing_denied'], list(OTHER_ALIASES))
        self.assertEqual(result['enrollment_status'], 'CANDIDATE_REQUIRES_REVIEW')
        self.assertEqual(result['approval_receipts_created'], 0)
        self.assertEqual(result['challenge']['kind'], 'identity_challenge')
        self.assertEqual(self.calls[0]['MessageType'], 'RAW')

    def test_wrong_identity_stops_before_sign(self):
        self.caller = ROLE.replace('spec-reviewer', 'inspector') + 'fixture'
        with self.assertRaises(StateError): self.execute()
        self.assertEqual(self.calls, [])

    def test_corrupt_signature_rejected(self):
        self.bad_signature = True
        with self.assertRaises(StateError): self.execute()

    def test_changed_public_key_pin_stops_before_sign(self):
        with patch('scripts.spec_signing_canary.FINGERPRINT', 'sha256:' + '0' * 64):
            with self.assertRaises(StateError): self.execute()
        self.assertEqual(self.calls, [])

    def test_cross_role_access_fails_canary(self):
        self.cross_allowed = True
        with self.assertRaises(StateError): self.execute()

    def test_other_aws_error_is_not_denial_proof(self):
        self.error_code = 'ThrottlingException'
        with self.assertRaises(AwsError): self.execute()

    def test_rerun_and_naive_time_rejected(self):
        with self.assertRaises(StateError): self.execute(run_id='123-2')
        with self.assertRaises(StateError): self.execute(now=NOW.replace(tzinfo=None))
        self.assertEqual(self.calls, [])
