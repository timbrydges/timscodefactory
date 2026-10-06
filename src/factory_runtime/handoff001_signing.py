"""Exact-role KMS signing adapter for live workflow observations only."""
import re
from factory_state.kms_signer import ALGORITHM, public_pem
from factory_state.model import StateError
from factory_state.scope import SignedScopeStore, canonical
from .handoff001_packets import TASK, CONTRACT, PINNED
from .handoff001_receipts import IDENTITIES

KEYS = {
    'builder': 'arn:aws:kms:ca-central-1:666730517561:key/9c24941f-563b-4dc9-bcc3-394384c655eb',
    'inspector': 'arn:aws:kms:ca-central-1:666730517561:key/7885556b-627c-4d95-a635-8849477fc00e',
    'qa': 'arn:aws:kms:ca-central-1:666730517561:key/71cb555e-37e8-44ec-b638-86072e3231c6'}
SIGNING_ROLES = {'builder': 'tims-factory-signing-builder',
    'inspector': 'tims-factory-signing-inspector', 'qa': 'tims-factory-review-qa'}


def assert_session(sts, role_name):
    caller = sts.get_caller_identity()
    prefix = 'arn:aws:sts::666730517561:assumed-role/' + role_name + '/'
    arn = caller.get('Arn', '')
    if (caller.get('Account') != '666730517561' or not isinstance(arn, str) or
            not arn.startswith(prefix) or not arn[len(prefix):] or '/' in arn[len(prefix):]):
        raise StateError('Handoff isolated AWS role identity differs')


class HandoffKmsSigner:
    """The deployed handler owns this adapter; it is not a public signing API."""
    def __init__(self, *, role, kms, sts, trusted_keys, model_id, source_commit,
                 request_digest, predecessor_receipt_digest):
        if role not in IDENTITIES: raise StateError('Unknown handoff signing role')
        self.role, self.kms, self.sts = role, kms, sts
        self.key = KEYS[role]
        self.identity = IDENTITIES[role]
        self.scope = SignedScopeStore('unused', None, trusted_keys)
        assert_session(sts, SIGNING_ROLES[role])
        if public_pem(kms.get_public_key(KeyId=self.key), expected_arn=self.key) != trusted_keys.get(self.identity):
            raise StateError('Handoff KMS key differs from current enrollment')
        self.expected = {'kind': 'handoff001_role_result', 'task_id': TASK, 'role': role,
            'producer_identity': self.identity, 'model_id': model_id, 'source_commit': source_commit,
            'contract_digest': 'sha256:'+PINNED[CONTRACT], 'request_digest': request_digest,
            'predecessor_receipt_digest': predecessor_receipt_digest, 'transport_invocations': 1}

    def sign(self, payload, *, now):
        extras = {'output_digest', 'provider_response_digest', 'actual_micro_usd', 'issued_at', 'expires_at'}
        if (not isinstance(payload, dict) or set(payload) != set(self.expected) | extras or
                any(type(payload.get(k)) is not type(v) or payload[k] != v for k, v in self.expected.items()) or
                type(payload['actual_micro_usd']) is not int or not 0 <= payload['actual_micro_usd'] <= 250000 or
                any(not isinstance(payload[k], str) or not re.fullmatch('sha256:[0-9a-f]{64}', payload[k])
                    for k in ('output_digest', 'provider_response_digest')) or
                type(payload['issued_at']) is not int or type(payload['expires_at']) is not int or
                now.tzinfo is None or not payload['issued_at'] <= now.timestamp() < payload['expires_at'] <= payload['issued_at']+3600):
            raise StateError('Handoff signing bindings or lifetime differ')
        raw = canonical(payload)
        if len(raw) > 4096: raise StateError('Handoff KMS receipt exceeds RAW limit')
        assert_session(self.sts, SIGNING_ROLES[self.role])
        result = self.kms.sign(KeyId=self.key, Message=raw, MessageType='RAW', SigningAlgorithm=ALGORITHM)
        if result.get('KeyId') != self.key or result.get('SigningAlgorithm') != ALGORITHM:
            raise StateError('Handoff KMS signing response identity differs')
        signature = result.get('Signature')
        self.scope._verify(payload, signature, self.identity, now)
        return signature
