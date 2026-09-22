"""Lambda entrypoint: bounded identity probes; operational role calls fail closed.

A probe proves deployment/authentication/signing, not autonomous role execution.
The full RoleExecutionService is packaged but is not activated by this handler.
"""
import base64
import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path

from factory_state.kms_signer import EnrolledKmsReceiptSigner, SIGNERS
from factory_state.model import StateError


def validate_probe(event, *, role, commit):
    if (role not in {'planner', 'builder', 'inspector'} or
            not isinstance(event, dict) or set(event) != {'kind', 'source_commit', 'nonce'} or
            event['kind'] != 'identity_probe' or event['source_commit'] != commit or
            not isinstance(event['nonce'], str) or not re.fullmatch(r'[a-zA-Z0-9-]{16,64}', event['nonce'])):
        raise StateError('only the bounded deployment identity probe is enabled')


def handle_probe(event, *, role, commit, signer, now):
    validate_probe(event, role=role, commit=commit)
    if signer.identity != SIGNERS[role]:
        raise StateError('deployed role signer mismatch')
    payload = {'kind': 'identity_challenge', 'identity': signer.identity,
        'source_commit': commit, 'nonce': event['nonce'], 'purpose': 'lambda-deployment-verification-only',
        'issued_at': int(now.timestamp()), 'expires_at': int(now.timestamp()) + 300}
    signature = signer.sign(payload, now=now)
    return {'payload': payload, 'signature_base64': base64.b64encode(signature).decode(),
            'model_calls': 0, 'operational_execution_enabled': False}


def handler(event, context):
    import boto3
    from botocore.config import Config
    root = Path(os.environ.get('LAMBDA_TASK_ROOT', '/var/task'))
    commit = json.loads((root/'BUILD.json').read_text())['source_commit']
    role = os.environ['FACTORY_ROLE']
    if role not in {'planner', 'builder', 'inspector'}:
        raise StateError('invalid deployed role')
    validate_probe(event, role=role, commit=commit)
    config = Config(connect_timeout=3, read_timeout=5, retries={'total_max_attempts': 1, 'mode': 'standard'})
    # Execution credentials cannot sign or modify controller state. A short-lived
    # role-specific signing session has no state, provider or deployment rights.
    sts = boto3.client('sts', region_name='ca-central-1', config=config)
    response = sts.assume_role(RoleArn=f'arn:aws:iam::666730517561:role/tims-factory-signing-{role}',
        RoleSessionName=f'lambda-{role}-{context.aws_request_id}', DurationSeconds=900)
    creds = response['Credentials']
    session = boto3.Session(aws_access_key_id=creds['AccessKeyId'], aws_secret_access_key=creds['SecretAccessKey'],
                            aws_session_token=creds['SessionToken'], region_name='ca-central-1')
    signer = EnrolledKmsReceiptSigner(session.client('kms', config=config), session.client('sts', config=config),
        signer=role, registry_path=root/'factory/profiles/scope-signers.json',
        bindings_path=root/'factory/profiles/kms-signers.json')
    return handle_probe(event, role=role, commit=commit, signer=signer, now=datetime.now(timezone.utc))
