import unittest
from unittest.mock import Mock
from factory_runtime.handoff001_signing import HandoffKmsSigner, KEYS, SIGNING_ROLES
from factory_state.model import StateError
from factory_state.signers import public_key_der
import test_handoff001_receipts as receipt_fixtures


class HandoffSigningTests(unittest.TestCase):
    def setUp(self):
        self.fixture = receipt_fixtures.HandoffReceiptTests()
        self.fixture.setUp()
        self.kms, self.sts = Mock(), Mock()

    def signer(self, role='builder'):
        payload = self.fixture.chain[role]['payload']
        self.sts.get_caller_identity.return_value = {'Account': '666730517561',
            'Arn': 'arn:aws:sts::666730517561:assumed-role/'+SIGNING_ROLES[role]+'/test'}
        pem = self.fixture.keys[payload['producer_identity']]
        self.kms.get_public_key.return_value = {'KeyId': KEYS[role], 'KeyUsage': 'SIGN_VERIFY',
            'KeySpec': 'ECC_NIST_EDWARDS25519', 'SigningAlgorithms': ['ED25519_SHA_512'],
            'PublicKey': public_key_der(pem)}
        self.kms.sign.side_effect = lambda **kw: {'KeyId': KEYS[role], 'SigningAlgorithm': 'ED25519_SHA_512',
            'Signature': self.fixture.private[role].sign(kw['Message'])}
        return HandoffKmsSigner(role=role, kms=self.kms, sts=self.sts, trusted_keys=self.fixture.keys,
            model_id=payload['model_id'], source_commit=payload['source_commit'],
            request_digest=payload['request_digest'], predecessor_receipt_digest=payload['predecessor_receipt_digest'])

    def test_all_three_exact_roles_sign_and_verify(self):
        for role in KEYS:
            signer = self.signer(role)
            signature = signer.sign(self.fixture.chain[role]['payload'], now=self.fixture.now)
            self.assertEqual(len(signature), 64)
            self.assertEqual(self.kms.sign.call_args.kwargs['MessageType'], 'RAW')

    def test_changed_scope_and_cost_rejected_before_kms_sign(self):
        signer = self.signer()
        payload = self.fixture.chain['builder']['payload']
        for field, value in [('task_id', 'old-task'), ('role', 'qa'), ('actual_micro_usd', 250001),
            ('request_digest', 'sha256:'+'f'*64), ('transport_invocations', True)]:
            with self.subTest(field=field), self.assertRaises(StateError):
                signer.sign({**payload, field: value}, now=self.fixture.now)
        self.kms.sign.assert_not_called()

    def test_role_identity_rechecked_at_sign_time(self):
        signer = self.signer()
        self.sts.get_caller_identity.return_value['Arn'] = 'arn:aws:iam::666730517561:root'
        with self.assertRaises(StateError): signer.sign(self.fixture.chain['builder']['payload'], now=self.fixture.now)
        self.kms.sign.assert_not_called()
