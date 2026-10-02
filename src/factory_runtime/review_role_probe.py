"""Disabled QA/security bootstrap: fixed identity challenges, never verdicts.

Bootstrap keys are deliberately not enrolled in the operational signer registry.
Their public fingerprints and cloud identities must be verified before enrollment.
"""
import base64
import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path

from factory_state.kms_signer import ALGORITHM, KEY_ARN, public_pem
from factory_state.model import StateError
from factory_state.scope import SignedScopeStore, canonical

IDENTITIES = {'qa': 'qa_engineer_service', 'security': 'deep_security_reviewer_service'}
FLAG = 'FACTORY_OPERATIONAL_EXECUTION_ENABLED'


def validate(event, *, role, commit, flag, key_arn):
    if (flag != 'false' or role not in IDENTITIES or not isinstance(commit, str) or
            not re.fullmatch('[0-9a-f]{40}', commit) or
            not isinstance(key_arn, str) or not KEY_ARN.fullmatch(key_arn) or
            not isinstance(event, dict) or set(event) != {'kind', 'source_commit', 'nonce'} or
            event['kind'] != 'review_role_identity_probe' or event['source_commit'] != commit or
            not isinstance(event['nonce'], str) or not re.fullmatch('[0-9a-f]{32}', event['nonce'])):
        raise StateError('only the disabled QA/security identity challenge is accepted')


def probe(event, *, role, commit, flag, key_arn, kms, sts, now):
    validate(event, role=role, commit=commit, flag=flag, key_arn=key_arn)
    if now.tzinfo is None or now.utcoffset() is None:
        raise StateError('probe time must be aware')
    caller = sts.get_caller_identity()
    prefix = f'arn:aws:sts::666730517561:assumed-role/tims-factory-review-{role}/'
    if (caller.get('Account') != '666730517561' or not isinstance(caller.get('Arn'), str) or
            not caller['Arn'].startswith(prefix) or not caller['Arn'][len(prefix):] or
            '/' in caller['Arn'][len(prefix):]):
        raise StateError('review role cloud identity differs')
    pem = public_pem(kms.get_public_key(KeyId=key_arn), expected_arn=key_arn)
    payload = {'kind': 'identity_challenge', 'identity': IDENTITIES[role],
        'purpose': 'disabled-review-role-bootstrap-only', 'source_commit': commit,
        'nonce': event['nonce'], 'key_arn': key_arn,
        'issued_at': int(now.timestamp()), 'expires_at': int(now.timestamp()) + 300}
    result = kms.sign(KeyId=key_arn, Message=canonical(payload),
                      MessageType='RAW', SigningAlgorithm=ALGORITHM)
    if result.get('KeyId') != key_arn or result.get('SigningAlgorithm') != ALGORITHM:
        raise StateError('KMS signing response differs')
    signature = result.get('Signature')
    SignedScopeStore('unused', None, {IDENTITIES[role]: pem})._verify(
        payload, signature, IDENTITIES[role], now)
    return {'payload': payload, 'signature_base64': base64.b64encode(signature).decode(),
        'model_calls': 0, 'state_writes': 0, 'operational_execution_enabled': False,
        'scope_approval': False, 'production_release_authorized': False}


def handler(event, context):
    root = Path(os.environ.get('LAMBDA_TASK_ROOT', '/var/task'))
    commit = json.loads((root / 'BUILD.json').read_bytes())['source_commit']
    args = {'role': os.environ.get('FACTORY_REVIEW_ROLE'), 'commit': commit,
            'flag': os.environ.get(FLAG), 'key_arn': os.environ.get('FACTORY_REVIEW_KEY_ARN')}
    validate(event, **args)  # Reject operational events before constructing AWS clients.
    import boto3
    from botocore.config import Config
    config = Config(connect_timeout=5, read_timeout=10,
                    retries={'total_max_attempts': 1, 'mode': 'standard'})
    session = boto3.Session(region_name='ca-central-1')
    return probe(event, **args, now=datetime.now(timezone.utc),
        kms=session.client('kms', endpoint_url='https://kms.ca-central-1.amazonaws.com', config=config),
        sts=session.client('sts', endpoint_url='https://sts.ca-central-1.amazonaws.com', config=config))
