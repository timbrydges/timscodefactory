"""Lambda entrypoint for identity and durable model-free transport canaries.

The canaries prove deployment, authentication, signing, persistence and replay
protection. The full RoleExecutionService is packaged but remains disabled.
"""
import base64
import hashlib
import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path

from factory_state.kms_signer import EnrolledKmsReceiptSigner, SIGNERS
from factory_state.model import StateError
from factory_state.scope import canonical

MAX_CANARY_INPUT = 4096
OPERATIONAL_FLAG = 'FACTORY_OPERATIONAL_EXECUTION_ENABLED'


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


def handle_operational_boundary_probe(event, *, role, commit, signer, now):
    expected = {'kind', 'source_commit', 'nonce', 'task_id'}
    if (role != 'builder' or not isinstance(event, dict) or set(event) != expected or
            event.get('kind') != 'operational_boundary_probe' or
            event.get('source_commit') != commit or
            event.get('task_id') != 'deterministic-text-fingerprint' or
            not isinstance(event.get('nonce'), str) or
            not re.fullmatch(r'[a-zA-Z0-9-]{16,64}', event['nonce']) or
            signer.identity != SIGNERS['builder']):
        raise StateError('invalid operational boundary probe')
    payload = {'kind': 'operational_boundary_attestation',
        'producer_identity': SIGNERS['builder'], 'source_commit': commit,
        'nonce': event['nonce'], 'task_id': event['task_id'],
        'target_alias': 'coding_primary_sol_live', 'model_id': 'gpt-5.6-sol',
        'maximum_cost_usd_per_call': '0.25', 'maximum_provider_calls': 3,
        'maximum_request_bytes': 42020, 'provider_credentials_in_role': False,
        'operational_execution_enabled': False,
        'purpose': 'operational-boundary-deployment-verification-only',
        'issued_at': int(now.timestamp()), 'expires_at': int(now.timestamp()) + 300}
    return {'payload': payload, 'signature_base64': base64.b64encode(
        signer.sign(payload, now=now)).decode(), 'model_calls': 0,
        'operational_execution_enabled': False}


def _transport_event(event, *, role, commit):
    if (role not in {'planner', 'builder', 'inspector'} or not isinstance(event, dict) or
            set(event) != {'kind', 'source_commit', 'nonce', 'input_base64'} or
            event['kind'] != 'transport_canary' or event['source_commit'] != commit or
            not isinstance(event['nonce'], str) or not re.fullmatch(r'[a-zA-Z0-9-]{16,64}', event['nonce']) or
            not isinstance(event['input_base64'], str) or len(event['input_base64']) > 5500):
        raise StateError('invalid bounded transport canary')
    try:
        raw = base64.b64decode(event['input_base64'], validate=True)
    except (ValueError, TypeError) as error:
        raise StateError('invalid transport canary input') from error
    if len(raw) > MAX_CANARY_INPUT:
        raise StateError('transport canary input exceeds limit')
    return raw


def _digest(raw):
    return 'sha256:' + hashlib.sha256(raw).hexdigest()


def handle_transport(event, *, role, commit, signer, now, database, table):
    raw = _transport_event(event, role=role, commit=commit)
    identity = SIGNERS[role]
    if signer.identity != identity or not isinstance(table, str) or not table:
        raise StateError('transport canary deployment mismatch')
    key = {'PK': {'S': f'ROLE#{identity}#FACTORY#tims-software-factory#TASK#cloud-role-canary-{event["nonce"]}'},
           'SK': {'S': 'EXECUTION#transport-canary'}}
    event_digest = _digest(canonical(event))
    item = {**key, 'status': {'S': 'STARTED'}, 'event_digest': {'S': event_digest},
            'identity': {'S': identity}, 'model_calls': {'N': '0'}}
    try:
        database.put_item(TableName=table, Item=item,
            ConditionExpression='attribute_not_exists(PK) AND attribute_not_exists(SK)')
    except Exception as error:
        if getattr(error, 'response', {}).get('Error', {}).get('Code') != 'ConditionalCheckFailedException':
            raise
        prior = database.get_item(TableName=table, Key=key, ConsistentRead=True).get('Item', {})
        if (prior.get('event_digest') != {'S': event_digest} or prior.get('identity') != {'S': identity}):
            raise StateError('transport canary binding conflict') from error
        if prior.get('status') != {'S': 'COMPLETE'} or 'response' not in prior:
            raise StateError('transport canary outcome unknown') from error
        return json.loads(prior['response']['S'])
    output = canonical({'input_digest': _digest(raw), 'role': role, 'status': 'transport_verified'})
    payload = {'kind': 'transport_result', 'producer_identity': identity,
        'source_commit': commit, 'nonce': event['nonce'], 'input_digest': _digest(raw),
        'output_digest': _digest(output), 'purpose': 'lambda-transport-canary-only',
        'issued_at': int(now.timestamp()), 'expires_at': int(now.timestamp()) + 300}
    response = {'payload': payload, 'signature_base64': base64.b64encode(
        signer.sign(payload, now=now)).decode(), 'output_base64': base64.b64encode(output).decode(),
        'model_calls': 0, 'operational_execution_enabled': False}
    database.update_item(TableName=table, Key=key,
        UpdateExpression='SET #s=:done, #r=:response',
        ConditionExpression='#s=:started AND event_digest=:digest AND #i=:identity',
        ExpressionAttributeNames={'#s': 'status', '#r': 'response', '#i': 'identity'},
        ExpressionAttributeValues={':done': {'S': 'COMPLETE'}, ':started': {'S': 'STARTED'},
            ':response': {'S': canonical(response).decode()}, ':digest': {'S': event_digest},
            ':identity': {'S': identity}})
    return response


def handler(event, context):
    import boto3
    from botocore.config import Config
    root = Path(os.environ.get('LAMBDA_TASK_ROOT', '/var/task'))
    commit = json.loads((root/'BUILD.json').read_text())['source_commit']
    role = os.environ['FACTORY_ROLE']
    if role not in {'planner', 'builder', 'inspector'}:
        raise StateError('invalid deployed role')
    if os.environ.get(OPERATIONAL_FLAG) != 'false':
        raise StateError('operational role kill switch must remain false')
    if not isinstance(event, dict) or event.get('kind') not in {
            'identity_probe', 'transport_canary', 'operational_boundary_probe'}:
        raise StateError('unsupported role invocation')
    if event['kind'] == 'identity_probe':
        validate_probe(event, role=role, commit=commit)
    elif event['kind'] == 'transport_canary':
        _transport_event(event, role=role, commit=commit)
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
    now = datetime.now(timezone.utc)
    if event['kind'] == 'identity_probe':
        return handle_probe(event, role=role, commit=commit, signer=signer, now=now)
    if event['kind'] == 'operational_boundary_probe':
        return handle_operational_boundary_probe(
            event, role=role, commit=commit, signer=signer, now=now)
    database = boto3.client('dynamodb', region_name='ca-central-1', config=config)
    return handle_transport(event, role=role, commit=commit, signer=signer, now=now,
        database=database, table=os.environ['EXECUTION_TABLE'])
