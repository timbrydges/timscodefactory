"""Inert immutable-version permission proof; no model, signing or writable request."""
import json
import os
from pathlib import Path
import re
from .handoff001_attempts import TABLE, ROLES, key
from .handoff001_entrypoint import ACCOUNT, REGION, EXECUTION_ROLES, _client
from .pilot002_entrypoint import _aws_session
from factory_state.model import StateError

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
    role = env.get('FACTORY_HANDOFF001_ROLE')
    name = 'tims-factory-handoff-001-'+str(role)
    prefix = f'arn:aws:lambda:{REGION}:{ACCOUNT}:function:{name}:'
    arn = getattr(context, 'invoked_function_arn', '')
    if (env.get('FACTORY_HANDOFF001_ENABLED') != 'false' or
            env.get('FACTORY_HANDOFF001_MODE') != 'permissions_canary' or role not in ROLES or
            env.get('AWS_REGION') != REGION or env.get('AWS_LAMBDA_FUNCTION_NAME') != name or
            not arn.startswith(prefix) or not re.fullmatch('[1-9][0-9]*', arn[len(prefix):])):
        raise StateError('Explicit disabled immutable canary required')
    source = json.loads((root/'BUILD.json').read_bytes())['source_commit']
    if event != {'kind':'handoff001_permissions_only','source_commit':source}:
        raise StateError('Canary event differs')
    session = _aws_session(env)
    from .handoff001_signing import assert_session
    assert_session(_client(session,'sts'), EXECUTION_ROLES[role])
    rows = probe(_client(session,'dynamodb'),role)
    return {'status':'HANDOFF_PERMISSION_CANARY_VERIFIED','role':role,'source_commit':source,
        'attempt_row_checks':rows,'state_writes':0,'model_calls':0,'signing_calls':0,
        'execution_authorized':False}


def handler(event, context):
    return dispatch(event,context,env=os.environ,root=Path(os.environ.get('LAMBDA_TASK_ROOT','/var/task')))
