"""Opt-in executor provenance for fixed QA tests; never a lease or gate verdict.

One operator invocation requires an external exclusive journal. This handler has
no durable replay ledger and must not be exposed as a one-shot signing service.
"""
import base64
import hashlib
import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path

from factory_state.kms_signer import ALGORITHM, public_pem
from factory_state.model import StateError
from factory_state.scope import SignedScopeStore, canonical
from factory_state.signers import validate_trusted_signers
from .implementation_inspector import CANDIDATE
from .qa_enrollment import IDENTITY, KEY, REGISTRY
from .qa_evidence import validate_execution
from .qa_execution import execute
from .review_preparation import prepare

FLAG = 'FACTORY_QA_ATTESTATION_ENABLED'


def validate(event, *, commit, env, now):
    nonce = env.get('FACTORY_QA_ATTESTATION_NONCE', '')
    deadline = env.get('FACTORY_QA_ATTESTATION_EXPIRES_AT', '')
    if (now.tzinfo is None or now.utcoffset() is None or
            env.get(FLAG) != 'true' or env.get('FACTORY_REVIEW_ROLE') != 'qa' or
            env.get('FACTORY_OPERATIONAL_EXECUTION_ENABLED') != 'false' or
            env.get('FACTORY_REVIEW_KEY_ARN') != KEY or
            not isinstance(commit, str) or not re.fullmatch('[0-9a-f]{40}', commit) or
            not re.fullmatch('[0-9a-f]{32}', nonce) or
            not re.fullmatch('[0-9]{10}', deadline) or
            not 0 < int(deadline) - now.timestamp() <= 300 or
            event != {'kind':'qa_execution_attestation', 'source_commit':commit,
                      'candidate_commit':CANDIDATE, 'nonce':nonce}):
        raise StateError('QA attestation requires exact approved source, nonce and five-minute window')
    return int(deadline)


def attest(event, *, root, commit, env, kms, sts, clock):
    now = clock()
    deadline = validate(event, commit=commit, env=env, now=now)
    raw = (root/REGISTRY).read_bytes()
    registry = json.loads(raw)
    keys = validate_trusted_signers(registry, now=now)
    entry = next((e for e in registry['signers'] if e['identity'] == IDENTITY), None)
    if IDENTITY not in keys or deadline > entry['expires_at']:
        raise StateError('QA attestation exceeds active signer enrollment')
    caller = sts.get_caller_identity()
    prefix = 'arn:aws:sts::666730517561:assumed-role/tims-factory-review-qa/'
    arn = caller.get('Arn', '')
    if (caller.get('Account') != '666730517561' or not isinstance(arn, str) or
            not arn.startswith(prefix) or not arn[len(prefix):] or '/' in arn[len(prefix):]):
        raise StateError('QA executor cloud identity differs')
    if public_pem(kms.get_public_key(KeyId=KEY), expected_arn=KEY) != keys[IDENTITY]:
        raise StateError('QA executor key differs from enrolled public key')
    packet = prepare(root, role='qa')
    report = execute(root, packet=packet)
    passed = validate_execution(report, packet, root=root)
    now = clock()  # Tests may outlive either approval or enrollment.
    validate(event, commit=commit, env=env, now=now)
    if validate_trusted_signers(registry, now=now).get(IDENTITY) != keys[IDENTITY]:
        raise StateError('QA signer expired during execution')
    payload = {'kind':'qa_execution_attestation', 'purpose':'executor-provenance-only',
        'identity':IDENTITY, 'key_arn':KEY, 'executor_arn':arn,
        'source_commit':commit, 'nonce':event['nonce'],
        'candidate_commit':CANDIDATE, 'contract_digest':packet['contract_digest'],
        'packet_digest':packet['packet_digest'], 'report_digest':report['report_digest'],
        'registry_sha256':hashlib.sha256(raw).hexdigest(),
        'cases_passed':passed, 'case_count':18,
        'issued_at':int(now.timestamp()), 'expires_at':deadline,
        'gate_authority':False, 'production_release_authorized':False}
    message = canonical(payload)
    if len(message) > 4096:
        raise StateError('QA attestation exceeds KMS RAW message bound')
    try:
        result = kms.sign(KeyId=KEY, Message=message, MessageType='RAW', SigningAlgorithm=ALGORITHM)
        if result.get('KeyId') != KEY or result.get('SigningAlgorithm') != ALGORITHM:
            raise StateError('QA signing response differs')
        signature = result.get('Signature')
        SignedScopeStore('unused', None, keys)._verify(payload, signature, IDENTITY, clock())
    except Exception:
        raise StateError('QA signing outcome uncertain; preserve invocation journal and never retry') from None
    return {'payload':payload, 'signature_base64':base64.b64encode(signature).decode(),
        'report':report, 'signing_calls':1, 'model_calls':0, 'task_state_writes':0,
        'gate_authority':False, 'production_release_authorized':False}


def handler(event, context):
    # Disabled by default, including when accidentally installed on the QA role.
    if os.environ.get(FLAG) != 'true':
        raise StateError('QA attestation signing is disabled')
    root = Path(os.environ.get('LAMBDA_TASK_ROOT', '/var/task'))
    commit = json.loads((root/'BUILD.json').read_bytes())['source_commit']
    clock = lambda: datetime.now(timezone.utc)
    validate(event, commit=commit, env=os.environ, now=clock())
    import boto3
    from botocore.config import Config
    config = Config(connect_timeout=5, read_timeout=10,
                    retries={'total_max_attempts':1, 'mode':'standard'})
    session = boto3.Session(region_name='ca-central-1')
    return attest(event, root=root, commit=commit, env=os.environ, clock=clock,
        kms=session.client('kms', endpoint_url='https://kms.ca-central-1.amazonaws.com', config=config),
        sts=session.client('sts', endpoint_url='https://sts.ca-central-1.amazonaws.com', config=config))
