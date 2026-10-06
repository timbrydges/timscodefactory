"""Prove new spec-reviewer key custody; never issue scope approval or enroll a key."""
import base64
import hashlib
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scripts.kms_signing_canary import AwsError, AwsJsonClient
from factory_state.kms_signer import ACCOUNT, ALGORITHM, KEY_ARN, public_pem
from factory_state.model import StateError
from factory_state.scope import SignedScopeStore, canonical
from factory_state.signers import public_key_der

IDENTITY = 'product_spec_reviewer_service'
ROLE = f'arn:aws:sts::{ACCOUNT}:assumed-role/tims-factory-signing-spec-reviewer/'
KEY = 'arn:aws:kms:ca-central-1:666730517561:key/76066708-e1ef-47c9-98fb-f38003c99d30'
FINGERPRINT = 'sha256:116b7ae802ec2bb9b484b56c68ea0a258cd900d1d426e41a9a22fd1764be5cbd'
OTHER_ALIASES = tuple('alias/tims-factory-signing-' + role for role in
                      ('owner', 'planner', 'builder', 'inspector')) + ('alias/tims-factory-review-qa',)


def run(run_id, commit, *, kms=None, sts=None, now=None):
    if not re.fullmatch(r'[0-9]+-1', run_id) or not re.fullmatch(r'[a-f0-9]{40}', commit):
        raise StateError('first workflow attempt and exact source required')
    now = now or datetime.now(timezone.utc)
    if now.tzinfo is None or now.utcoffset() is None:
        raise StateError('aware signing time required')
    kms, sts = kms or AwsJsonClient('kms'), sts or AwsJsonClient('sts')

    def caller():
        value = sts.get_caller_identity()
        arn = value.get('Arn', '')
        if (value.get('Account') != ACCOUNT or not arn.startswith(ROLE) or
                not arn[len(ROLE):] or '/' in arn[len(ROLE):]):
            raise StateError('isolated spec reviewer session required')
        return arn

    arn = caller()
    response = kms.get_public_key(KeyId=KEY)
    key = response.get('KeyId', '')
    if not KEY_ARN.fullmatch(key) or key != KEY:
        raise StateError('unexpected signing key account or region')
    pem = public_pem(response, expected_arn=key)
    fingerprint = 'sha256:' + hashlib.sha256(public_key_der(pem)).hexdigest()
    if fingerprint != FINGERPRINT:
        raise StateError('public key differs from approved resource evidence')
    payload = {'kind': 'identity_challenge', 'identity': IDENTITY,
               'source_commit': commit, 'workflow_run': run_id,
               'issued_at': int(now.timestamp()), 'expires_at': int(now.timestamp()) + 600,
               'purpose': 'key-custody-verification-only'}
    if caller() != arn:
        raise StateError('signing session changed')
    result = kms.sign(KeyId=key, Message=canonical(payload), MessageType='RAW',
                      SigningAlgorithm=ALGORITHM)
    if result.get('KeyId') != key or result.get('SigningAlgorithm') != ALGORITHM:
        raise StateError('unexpected KMS response binding')
    signature = result.get('Signature')
    SignedScopeStore('unused', None, {IDENTITY: pem})._verify(payload, signature, IDENTITY, now)
    denied = []
    for other in OTHER_ALIASES:
        try:
            kms.sign(KeyId=other, Message=canonical(payload), MessageType='RAW',
                     SigningAlgorithm=ALGORITHM)
        except AwsError as error:
            if error.code != 'AccessDeniedException':
                raise
            denied.append(other)
        else:
            raise StateError('cross-role signing unexpectedly succeeded')
    return {'conclusion': 'success', 'source_commit': commit, 'workflow_run': run_id,
            'identity': IDENTITY, 'aws_caller_arn': arn, 'key_arn': key,
            'public_key_pem': pem.decode(),
            'fingerprint': fingerprint,
            'challenge': payload, 'signature_base64': base64.b64encode(signature).decode(),
            'cross_role_signing_denied': denied, 'enrollment_status': 'CANDIDATE_REQUIRES_REVIEW',
            'model_calls': 0, 'approval_receipts_created': 0}


if __name__ == '__main__':
    import json
    print(json.dumps(run(*sys.argv[1:]), indent=2))
