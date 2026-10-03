"""Gated broker integration. No production activation manifest is pinned yet."""
import hashlib
import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path

from factory_state.model import OWNER_IDENTITY, StateError
from factory_state.signers import validate_trusted_signers
from .google_qa import GoogleQATransport
from .google_qa_authorization import verify
from .google_qa_boundary import ACTIVATION, FLAG, TABLE, handler as disabled_handler
from .google_qa_reservation import GoogleQaReservedAttemptStore
from .google_qa_workflow import run_once
from .review_preparation import prepare

MANIFEST = 'factory/evidence/google-qa-runtime-activation.json'
# A reviewed source change must install qualified pricing and pin these bytes.
# Invocation fields and environment variables cannot supply or override this pin.
ACTIVE_MANIFEST_SHA256 = None
SECRET_ARN = 'arn:aws:secretsmanager:ca-central-1:666730517561:secret:tims-software-factory/provider/google/qa-rYGeOE'
SECRET_VERSION = 'db69f4bf-38c0-43d5-8bbf-ce20d8e07282'
ROLE_PREFIX = 'arn:aws:sts::666730517561:assumed-role/tims-factory-google-qa-broker/'


def _read(path, limit):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result: raise StateError('duplicate broker configuration field')
            result[key] = value
        return result
    with path.open('rb') as stream:
        raw = stream.read(limit+1)
    if not 0 < len(raw) <= limit:
        raise StateError('broker configuration exceeds bound')
    return raw, json.loads(raw, object_pairs_hook=unique)


def configuration(root, now):
    if not isinstance(ACTIVE_MANIFEST_SHA256, str) or not re.fullmatch('[0-9a-f]{64}', ACTIVE_MANIFEST_SHA256):
        raise StateError('Google broker has no reviewed activation manifest')
    try:
        raw, manifest = _read(root/MANIFEST, 16000)
        if (hashlib.sha256(raw).hexdigest() != ACTIVE_MANIFEST_SHA256 or not isinstance(manifest, dict) or
                set(manifest) != {'activation_id','pricing','signer_registry_sha256','secret_arn','secret_version'} or
                manifest['activation_id'] != ACTIVATION or manifest['secret_arn'] != SECRET_ARN or
                manifest['secret_version'] != SECRET_VERSION):
            raise StateError('Google activation manifest differs')
        raw, registry = _read(root/'factory/profiles/scope-signers.json', 65536)
        if hashlib.sha256(raw).hexdigest() != manifest['signer_registry_sha256']:
            raise StateError('Google owner registry differs from reviewed activation')
        keys = validate_trusted_signers(registry, now=now)
        owner = next(entry for entry in registry['signers'] if entry['identity'] == OWNER_IDENTITY)
        if (OWNER_IDENTITY not in keys or not isinstance(manifest['pricing'],dict) or
                type(manifest['pricing'].get('expires_at')) is not int or
                manifest['pricing']['expires_at'] > owner['expires_at']):
            raise StateError('Google pricing window exceeds active owner enrollment')
        return manifest['pricing'], keys
    except Exception:
        raise StateError('Google broker configuration invalid or unavailable') from None


def aws_clients():
    import boto3
    from botocore.config import Config
    session = boto3.Session(region_name='ca-central-1')
    config = Config(connect_timeout=5, read_timeout=30, retries={'total_max_attempts':1})
    return {name:session.client(name, config=config) for name in ('sts','dynamodb','secretsmanager')}


def dispatch(event, *, root, clock, clients_factory=aws_clients):
    try:
        _, build = _read(root/'BUILD.json', 4096)
        commit = build['source_commit']
        if (not isinstance(commit,str) or not re.fullmatch('[0-9a-f]{40}',commit) or
                not isinstance(event,dict) or set(event) != {'kind','source_commit','allowance'} or
                event['kind'] != 'google_qa_review_once' or event['source_commit'] != commit):
            raise StateError('Google broker event differs')
        now = clock()
        pricing, keys = configuration(root, now)
        # Authenticate before creating clients or reaching any AWS operation.
        verify(event['allowance'], packet=prepare(root,role='qa'), root=root,
            source_commit=commit, pricing=pricing, trusted_keys=keys, now=now)
    except Exception:
        raise StateError('Google broker activation or authorization rejected before cloud access') from None
    try:
        clients = clients_factory()
        caller = clients['sts'].get_caller_identity()
        arn = caller.get('Arn')
        if (caller.get('Account') != '666730517561' or not isinstance(arn,str) or
                not arn.startswith(ROLE_PREFIX) or not arn[len(ROLE_PREFIX):] or '/' in arn[len(ROLE_PREFIX):]):
            raise StateError('Google broker session identity differs')
        def load_key():
            secret = clients['secretsmanager'].get_secret_value(
                SecretId=SECRET_ARN, VersionId=SECRET_VERSION, VersionStage='AWSCURRENT')
            if (secret.get('ARN') != SECRET_ARN or secret.get('VersionId') != SECRET_VERSION or
                    'AWSCURRENT' not in secret.get('VersionStages',[]) or
                    not isinstance(secret.get('SecretString'),str)):
                raise StateError('Google broker credential identity differs')
            return secret['SecretString']
        return run_once(event['allowance'], root=root, source_commit=commit,
            pricing=pricing, trusted_keys=keys,
            store=GoogleQaReservedAttemptStore(TABLE,clients['dynamodb']), load_key=load_key,
            transport=GoogleQATransport(), clock=clock)
    except Exception:
        raise StateError('Google broker execution uncertain or rejected; reconcile without retry') from None


def handler(event, context):
    if os.environ.get(FLAG) == 'false':
        return disabled_handler(event, context)
    if os.environ.get(FLAG) != 'true':
        raise StateError('Google broker enable flag invalid')
    return dispatch(event, root=Path(os.environ.get('LAMBDA_TASK_ROOT','/var/task')),
                    clock=lambda:datetime.now(timezone.utc))
