"""Factory role signing through non-exportable AWS KMS Ed25519 keys.

Only a trusted, authenticated role workflow may call this adapter after approving
the exact receipt semantics. Possession of a signing role is not a review verdict.
The controller receives public keys and signatures, never private key material.
"""
import base64
import hashlib
import re
import textwrap

from .model import StateError
from .scope import SignedScopeStore, canonical
from .signers import public_key_der

SIGNERS = {
    'owner': 'tim_brydges',
    'planner': 'software_architect_service',
    'builder': 'engineering_agent_service',
    'inspector': 'independent_inspector_service',
}
ACCOUNT = '666730517561'
REGION = 'ca-central-1'
ALGORITHM = 'ED25519_SHA_512'
KEY_ARN = re.compile(r'^arn:aws:kms:ca-central-1:666730517561:key/[a-f0-9-]{36}$')


def public_pem(response, *, expected_arn):
    if (response.get('KeyId') != expected_arn or response.get('KeyUsage') != 'SIGN_VERIFY' or
            response.get('KeySpec') != 'ECC_NIST_EDWARDS25519' or
            ALGORITHM not in response.get('SigningAlgorithms', [])):
        raise StateError('KMS key identity, usage or algorithm differs from enrollment')
    encoded = base64.b64encode(response['PublicKey']).decode('ascii')
    pem = ('-----BEGIN PUBLIC KEY-----\n' + '\n'.join(textwrap.wrap(encoded, 64)) +
           '\n-----END PUBLIC KEY-----\n').encode('ascii')
    public_key_der(pem)
    return pem


def assert_role_identity(sts, signer):
    if signer not in SIGNERS:
        raise StateError('unknown Factory signer')
    caller = sts.get_caller_identity()
    role = f'arn:aws:sts::{ACCOUNT}:assumed-role/tims-factory-signing-{signer}/'
    if (caller.get('Account') != ACCOUNT or not isinstance(caller.get('Arn'), str) or
            not caller['Arn'].startswith(role) or not caller['Arn'][len(role):] or
            '/' in caller['Arn'][len(role):]):
        raise StateError('signing session does not match the isolated role')
    return caller['Arn']


class KmsReceiptSigner:
    def __init__(self, kms, sts, *, signer, key_arn, expected_fingerprint):
        if not isinstance(key_arn, str) or not KEY_ARN.fullmatch(key_arn):
            raise StateError('signer requires an exact enrolled KMS key ARN')
        assert_role_identity(sts, signer)
        self.kms, self.sts, self.signer, self.key_arn = kms, sts, signer, key_arn
        self.identity = SIGNERS[signer]
        self.pem = public_pem(kms.get_public_key(KeyId=key_arn), expected_arn=key_arn)
        fingerprint = 'sha256:' + hashlib.sha256(public_key_der(self.pem)).hexdigest()
        if fingerprint != expected_fingerprint:
            raise StateError('KMS public key does not match reviewed enrollment')

    def sign(self, payload, *, now):
        kind = payload.get('kind')
        identity_field = {'capability': 'owner_identity', 'scope_review': 'reviewer_identity',
                          'role_result': 'producer_identity', 'identity_challenge': 'identity'}.get(kind)
        allowed = {'owner': {'capability', 'identity_challenge'},
                   'planner': {'role_result', 'identity_challenge'},
                   'builder': {'role_result', 'identity_challenge'},
                   'inspector': {'scope_review', 'role_result', 'identity_challenge'}}
        if kind not in allowed[self.signer] or payload.get(identity_field) != self.identity:
            raise StateError('signer cannot attest this receipt kind or identity')
        if (now.tzinfo is None or now.utcoffset() is None or
                type(payload.get('issued_at')) is not int or type(payload.get('expires_at')) is not int or
                not payload['issued_at'] <= now.timestamp() < payload['expires_at']):
            raise StateError('invalid signing receipt lifetime')
        raw = canonical(payload)
        if len(raw) > 4096:
            # RAW is essential: prehashing would change existing Ed25519 verification semantics.
            raise StateError('KMS RAW receipt exceeds 4096 bytes; use bounded evidence digests')
        assert_role_identity(self.sts, self.signer)
        response = self.kms.sign(KeyId=self.key_arn, Message=raw,
                                 MessageType='RAW', SigningAlgorithm=ALGORITHM)
        if response.get('KeyId') != self.key_arn or response.get('SigningAlgorithm') != ALGORITHM:
            raise StateError('unexpected KMS signing response identity')
        signature = response.get('Signature')
        SignedScopeStore('unused', None, {self.identity: self.pem})._verify(
            payload, signature, self.identity, now)
        return signature
