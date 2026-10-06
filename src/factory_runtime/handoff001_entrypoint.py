"""Disabled immutable-version Lambda boundary for the fresh handoff only."""
import base64
import hashlib
import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path

from factory_state.model import OWNER_IDENTITY, StateError
from factory_state.scope import canonical
from factory_state.signers import validate_trusted_signers
from .handoff001_attempts import Handoff001AttemptStore
from .handoff001_authorization import verify, validate_unsigned
from .handoff001_packets import facts
from .handoff001_protocols import packet, request_bytes
from .handoff001_receipts import IDENTITIES, sha, verify_predecessors
from .handoff001_signing import HandoffKmsSigner, SIGNING_ROLES, assert_session
from .handoff001_workflow import prepare_pricing, run_once, HandoffStopped
from .pilot002_entrypoint import _read, _pairs, _aws_session, _credential

REGION = 'ca-central-1'
ACCOUNT = '666730517561'
ACTIVATION = 'HANDOFF001_ACTIVATION.json'
EXECUTION_ROLES = {'builder': 'tims-factory-executor-builder',
    'inspector': 'tims-factory-executor-inspector', 'qa': 'tims-factory-review-qa'}
SECRETS = {
    'builder': 'arn:aws:secretsmanager:ca-central-1:666730517561:secret:tims-software-factory/provider/openai/acceptance-WE57Tw',
    'qa': 'arn:aws:secretsmanager:ca-central-1:666730517561:secret:tims-software-factory/provider/google/qa-rYGeOE'}


def load_activation(root, env, now, *, allow_unsigned=False):
    facts(root)
    raw = _read(root, ACTIVATION, 262144)
    expected = env.get('FACTORY_HANDOFF001_ACTIVATION_SHA256', '')
    if not re.fullmatch('[0-9a-f]{64}', expected) or hashlib.sha256(raw).hexdigest() != expected:
        raise StateError('Handoff activation digest differs')
    doc = json.loads(raw, object_pairs_hook=_pairs)
    fields = {'schema_version', 'role', 'source_commit', 'qualification', 'readiness', 'allowance',
        'signer_registry', 'credential', 'predecessors', 'predecessor_request_digests', 'candidate_commit'}
    if not isinstance(doc, dict) or set(doc) != fields or doc['schema_version'] != '1.0':
        raise StateError('Handoff activation schema differs')
    role = env.get('FACTORY_HANDOFF001_ROLE')
    source = doc['source_commit']
    if (role not in IDENTITIES or doc['role'] != role or not isinstance(source, str) or
            not re.fullmatch('[0-9a-f]{40}', source) or
            json.loads(_read(root, 'BUILD.json', 1024), object_pairs_hook=_pairs) != {'source_commit': source}):
        raise StateError('Handoff activation role or immutable source differs')
    all_keys = validate_trusted_signers(doc['signer_registry'], now=now)
    required = {OWNER_IDENTITY, *IDENTITIES.values()}
    if not required <= set(all_keys): raise StateError('Fresh owner and all role enrollments required')
    keys = {identity: all_keys[identity] for identity in required}
    route = doc['credential']
    if role == 'inspector':
        if route != {'kind': 'lambda_execution_role'}: raise StateError('Inspector credential route differs')
    elif (not isinstance(route, dict) or set(route) != {'kind', 'secret_arn', 'version_id', 'json_key'} or
            route['kind'] != 'secretsmanager' or route['secret_arn'] != SECRETS[role] or
            not isinstance(route['version_id'], str) or not re.fullmatch('[A-Za-z0-9-]{32,64}', route['version_id']) or
            route['json_key'] not in (None, 'api_key')):
        raise StateError('Handoff immutable credential route differs')
    builder_response = previous = None
    if role == 'builder':
        if any(doc[k] is not None for k in ('predecessors', 'predecessor_request_digests', 'candidate_commit')):
            raise StateError('Builder cannot accept review context')
    else:
        prior = verify_predecessors(doc['predecessors'], next_role=role, root=root, trusted_keys=keys,
            source_commit=source, candidate_commit=doc['candidate_commit'],
            request_digests=doc['predecessor_request_digests'], now=now)
        builder_response, previous = prior['builder_response'], prior['predecessor_receipt_digest']
    context = dict(role=role, builder_response=builder_response, candidate_commit=doc['candidate_commit'])
    request = request_bytes(root, **context)
    pricing = prepare_pricing(root, source_commit=source, qualification=doc['qualification'],
        predecessor_receipt_digest=previous, **context)
    bound = dict(root=root, source_commit=source, request_bytes=request, pricing=pricing,
        readiness=doc['readiness'], now=now, predecessor_receipt_digest=previous, **context)
    if allow_unsigned is True:
        envelope = doc['allowance']
        if not isinstance(envelope, dict) or set(envelope) != {'payload', 'signature'} or envelope['signature'] != '':
            raise StateError('Unsigned preparation requires an empty signature')
        validate_unsigned(envelope['payload'], **bound)
    else:
        verify(doc['allowance'], trusted_keys=keys, **bound)
    return doc, keys, packet(root, **context), sha(request), previous


def _client(session, service):
    from botocore.config import Config
    if service not in ('dynamodb', 'kms', 'sts'): raise StateError('Unexpected handoff AWS service')
    return session.client(service, region_name=REGION,
        endpoint_url='https://'+service+'.'+REGION+'.amazonaws.com',
        config=Config(retries={'total_max_attempts': 1}, connect_timeout=5, read_timeout=10, proxies={}))


def _signing_session(session, role):
    if role == 'qa': return session
    response = _client(session, 'sts').assume_role(
        RoleArn='arn:aws:iam::'+ACCOUNT+':role/'+SIGNING_ROLES[role],
        RoleSessionName='handoff001-'+role, DurationSeconds=900)
    import boto3
    credentials = response['Credentials']
    return boto3.Session(aws_access_key_id=credentials['AccessKeyId'],
        aws_secret_access_key=credentials['SecretAccessKey'], aws_session_token=credentials['SessionToken'],
        region_name=REGION)


def dispatch(event, context, *, root, env, clock):
    if env.get('FACTORY_HANDOFF001_ENABLED') != 'true':
        raise StateError('Handoff entry point disabled')
    role = env.get('FACTORY_HANDOFF001_ROLE')
    try:
        name = 'tims-factory-handoff-001-'+str(role)
        prefix = 'arn:aws:lambda:'+REGION+':'+ACCOUNT+':function:'+name+':'
        arn = context.invoked_function_arn
        if (role not in IDENTITIES or not isinstance(arn, str) or not arn.startswith(prefix) or
                not re.fullmatch('[1-9][0-9]*', arn[len(prefix):]) or
                context.get_remaining_time_in_millis() < 120000 or env.get('AWS_REGION') != REGION or
                env.get('AWS_LAMBDA_FUNCTION_NAME') != name):
            raise StateError('Handoff requires the exact role and immutable function version')
        if not isinstance(event, dict) or len(canonical(event)) > 2048:
            raise StateError('Handoff event size or schema differs')
        doc, keys, value, request_digest, previous = load_activation(root, env, clock())
        if event != {'kind': 'handoff001_run_once', 'source_commit': doc['source_commit'],
                'activation_sha256': env['FACTORY_HANDOFF001_ACTIVATION_SHA256']}:
            raise StateError('Handoff event binding differs')
        session = _aws_session(env)
        assert_session(_client(session, 'sts'), EXECUTION_ROLES[role])
        signing = _signing_session(session, role)
        signer = HandoffKmsSigner(role=role, kms=_client(signing, 'kms'), sts=_client(signing, 'sts'),
            trusted_keys=keys, model_id=value['model_id'], source_commit=doc['source_commit'],
            request_digest=request_digest, predecessor_receipt_digest=previous)
        return run_once(doc['allowance'], root=root, role=role, source_commit=doc['source_commit'],
            qualification=doc['qualification'], readiness=doc['readiness'], trusted_keys=keys,
            store=Handoff001AttemptStore(_client(session, 'dynamodb')),
            load_credential=lambda: _credential(session, doc['credential']), sign_receipt=signer.sign,
            clock=clock, enabled=True, predecessors=doc['predecessors'],
            predecessor_request_digests=doc['predecessor_request_digests'], candidate_commit=doc['candidate_commit'])
    except HandoffStopped as error:
        if error.response is not None:
            return {'status': 'HANDOFF_FAILED_NO_RETRY', 'role': role, 'failure_stage': error.stage,
                'provider_response_digest': sha(error.response),
                'provider_response_base64': base64.b64encode(error.response).decode(),
                'response_is_untrusted': True, 'attempt_reusable': False,
                'reservation_status': 'HELD', 'gate_authority': False}
        raise StateError(str(error)) from None
    except Exception:
        raise StateError('Handoff entry point stopped; reconcile without retry') from None


def handler(event, context):
    return dispatch(event, context, root=Path(os.environ.get('LAMBDA_TASK_ROOT', '/var/task')),
        env=os.environ, clock=lambda: datetime.now(timezone.utc))
