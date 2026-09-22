"""Factory role signing through non-exportable AWS KMS Ed25519 keys.

Only a trusted, authenticated role workflow may call this adapter after approving
the exact receipt semantics. Possession of a signing role is not a review verdict.
The controller receives public keys and signatures, never private key material.
"""
import base64
import hashlib
import json
import re
import textwrap

from .model import StateError
from .scope import SignedScopeStore, canonical
from .signers import public_key_der, validate_trusted_signers

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
                          'role_result': 'producer_identity', 'transport_result': 'producer_identity',
                          'identity_challenge': 'identity'}.get(kind)
        allowed = {'owner': {'capability', 'identity_challenge'},
                   'planner': {'role_result', 'transport_result', 'identity_challenge'},
                   'builder': {'role_result', 'transport_result', 'identity_challenge'},
                   'inspector': {'scope_review', 'role_result', 'transport_result', 'identity_challenge'}}
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


class EnrolledKmsReceiptSigner:
    """Role-side signer using trusted deployment paths, never task-supplied keys.

    Re-read enrollment before every signing request. This does not authorize a
    task or review: the role service must enforce its contract, pause and budget
    controls separately. No private material or signing credentials belong in
    the controller process.
    """

    def __init__(self, kms, sts, *, signer, registry_path, bindings_path):
        if signer not in SIGNERS:
            raise StateError('unknown Factory signer')
        self.kms, self.sts, self.signer = kms, sts, signer
        self.identity = SIGNERS[signer]
        self.registry_path, self.bindings_path = registry_path, bindings_path

    def _enrollment(self, now):
        registry = json.loads(self.registry_path.read_bytes())
        keys = validate_trusted_signers(registry, now=now)
        if self.identity not in keys:
            raise StateError('signing identity is revoked, expired or not enrolled')
        entries = {entry['identity']: entry for entry in registry['signers']}
        document = json.loads(self.bindings_path.read_bytes())
        if (set(document) != {'schema_version', 'signers'} or
                document['schema_version'] != '1.0' or not isinstance(document['signers'], list)):
            raise StateError('invalid KMS enrollment bindings')
        bindings, arns = {}, set()
        for entry in document['signers']:
            if (not isinstance(entry, dict) or set(entry) !=
                    {'signer', 'identity', 'key_arn', 'fingerprint', 'enrollment_commit'}):
                raise StateError('invalid KMS signer binding fields')
            role = entry['signer']
            if (not isinstance(role, str) or role not in SIGNERS or role in bindings or
                    entry['identity'] != SIGNERS[role] or not isinstance(entry['key_arn'], str) or
                    not KEY_ARN.fullmatch(entry['key_arn']) or entry['key_arn'] in arns):
                raise StateError('KMS signer role or exact key binding invalid')
            enrolled = entries.get(entry['identity'])
            if (enrolled is None or any(entry[field] != enrolled[field]
                    for field in ('fingerprint', 'enrollment_commit'))):
                raise StateError('KMS binding differs from reviewed public-key enrollment')
            bindings[role] = entry
            arns.add(entry['key_arn'])
        if self.signer not in bindings:
            raise StateError('KMS signing role is not enrolled')
        selected = bindings[self.signer]
        fingerprint = 'sha256:' + hashlib.sha256(public_key_der(keys[self.identity])).hexdigest()
        if selected['fingerprint'] != fingerprint:
            raise StateError('KMS enrollment changed while loading')
        return selected, keys[self.identity]

    def sign(self, payload, *, now):
        binding, pem = self._enrollment(now)
        signer = KmsReceiptSigner(self.kms, self.sts, signer=self.signer,
            key_arn=binding['key_arn'], expected_fingerprint=binding['fingerprint'])
        if signer.pem != pem:
            raise StateError('KMS public key differs from active enrollment')
        # Fail closed if enrollment changes during remote authentication/key reads.
        if self._enrollment(now) != (binding, pem):
            raise StateError('KMS enrollment changed before signing')
        return signer.sign(payload, now=now)
