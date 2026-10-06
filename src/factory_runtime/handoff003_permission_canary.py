"""Inert immutable-version permission proof; no model, signing or writable request."""
import json
import hashlib
import os
from pathlib import Path
import re
from .handoff003_attempts import TABLE, ROLES, key
from .handoff003_entrypoint import ACCOUNT, REGION, EXECUTION_ROLES, SECRETS, _client, _signing_session
from .handoff003_signing import KEYS, SIGNING_ROLES, assert_session
from .pilot002_entrypoint import _aws_session, _credential
from factory_state.kms_signer import public_pem
from factory_state.signers import public_key_der
from factory_state.model import StateError

VERSIONS = {'builder':'ebb6cc21-2df9-4b06-8f55-2b0661f27f69',
    'qa':'db69f4bf-38c0-43d5-8bbf-ce20d8e07282'}


def dependencies(session, role):
    if role in VERSIONS:
        credential = _credential(session, {'kind':'secretsmanager','secret_arn':SECRETS[role],
            'version_id':VERSIONS[role],'json_key':None})
        credential = None
    signing = _signing_session(session,role)
    assert_session(_client(signing,'sts'),SIGNING_ROLES[role])
    pem = public_pem(_client(signing,'kms').get_public_key(KeyId=KEYS[role]),expected_arn=KEYS[role])
    return {'credential_route_verified':True,'signing_key_readable':True,
        'key_fingerprint':'sha256:'+hashlib.sha256(public_key_der(pem)).hexdigest()}

def probe(db, role):
    """Both predicates cannot be true, including if a previous row exists."""
    decisions = []
    for target in ROLES:
        try:
            db.put_item(TableName=TABLE, Item=key(target),
                ConditionExpression='attribute_exists(PK) AND attribute_not_exists(PK)')
        except Exception as error:
            code = getattr(error, 'response', {}).get('Error', {}).get('Code')
            expected = 'ConditionalCheckFailedException' if target == role else 'AccessDeniedException'
            if code != expected:
                raise StateError('Handoff permission canary denied or inconclusive') from None
            decisions.append({'target_role':target,'decision':code})
        else:
            raise StateError('Impossible condition unexpectedly accepted; stop')
    return decisions


def dispatch(event, context, *, env, root):
    role = env.get('FACTORY_HANDOFF003_ROLE')
    name = 'tims-factory-handoff-003-'+str(role)
    prefix = f'arn:aws:lambda:{REGION}:{ACCOUNT}:function:{name}:'
    arn = getattr(context, 'invoked_function_arn', '')
    if (env.get('FACTORY_HANDOFF003_ENABLED') != 'false' or
            env.get('FACTORY_HANDOFF003_MODE') != 'permissions_canary' or role not in ROLES or
            env.get('AWS_REGION') != REGION or env.get('AWS_LAMBDA_FUNCTION_NAME') != name or
            not arn.startswith(prefix) or not re.fullmatch('[1-9][0-9]*', arn[len(prefix):])):
        raise StateError('Explicit disabled immutable canary required')
    source = json.loads((root/'BUILD.json').read_bytes())['source_commit']
    if event != {'kind':'handoff003_permissions_only','source_commit':source}:
        raise StateError('Canary event differs')
    session = _aws_session(env)
    assert_session(_client(session,'sts'), EXECUTION_ROLES[role])
    rows = probe(_client(session,'dynamodb'),role)
    ready = dependencies(session,role)
    return {'status':'HANDOFF_PERMISSION_CANARY_VERIFIED','role':role,'source_commit':source,
        'attempt_row_checks':rows,'dependencies':ready,'state_writes':0,'model_calls':0,'signing_calls':0,
        'execution_authorized':False}


def handler(event, context):
    try:
        return dispatch(event,context,env=os.environ,root=Path(os.environ.get('LAMBDA_TASK_ROOT','/var/task')))
    except Exception:
        raise StateError('Handoff permission or dependency canary failed; no provider call attempted') from None
