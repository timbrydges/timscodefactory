"""Disabled-by-default Lambda boundary; activation material is deployment-owned."""
import base64
import hashlib
import json
import os
from pathlib import Path
import re
from datetime import datetime, timezone

from factory_state.model import OWNER_IDENTITY, StateError
from factory_state.scope import canonical
from factory_state.signers import validate_trusted_signers
from .pilot002_adapter import Pilot002Adapter, run_bound_once
from .pilot002_authorization import verify
from .pilot002_attempts import Pilot002AttemptStore
from .pilot002_protocols import request_bytes

REGION='ca-central-1'
ACCOUNT='666730517561'
ACTIVATION='PILOT002_ACTIVATION.json'


def _pairs(pairs):
    result={}
    for key,value in pairs:
        if key in result:raise ValueError('duplicate JSON key')
        result[key]=value
    return result


def _read(root, name, limit):
    path=root/name
    if any(p.is_symlink() for p in (path,*path.parents)):raise ValueError('symlink')
    with path.open('rb') as stream:raw=stream.read(limit+1)
    if not 0<len(raw)<=limit:raise ValueError('size')
    return raw


def load_activation(root, env, now):
    raw=_read(root,ACTIVATION,131072)
    expected=env.get('FACTORY_PILOT002_ACTIVATION_SHA256','')
    if not re.fullmatch('[0-9a-f]{64}',expected) or hashlib.sha256(raw).hexdigest()!=expected:
        raise ValueError('activation digest')
    doc=json.loads(raw,object_pairs_hook=_pairs)
    fields={'schema_version','role','source_commit','qualification','readiness','signer_registry',
        'credential','builder_response_base64','candidate_commit'}
    if not isinstance(doc,dict) or set(doc)!=fields or doc['schema_version']!='1.0':raise ValueError('activation schema')
    role=env.get('FACTORY_PILOT002_ROLE')
    if role not in ('builder','inspector','qa') or doc['role']!=role:raise ValueError('role')
    build=json.loads(_read(root,'BUILD.json',1024),object_pairs_hook=_pairs)
    source=doc['source_commit']
    if not isinstance(source,str) or not re.fullmatch('[0-9a-f]{40}',source) or build!={'source_commit':source}:
        raise ValueError('source')
    keys=validate_trusted_signers(doc['signer_registry'],now=now)
    if set(keys)!={OWNER_IDENTITY}:raise ValueError('owner enrollment')
    credential=doc['credential']
    if role=='inspector':
        if credential!={'kind':'lambda_execution_role'}:raise ValueError('credential route')
    else:
        if (not isinstance(credential,dict) or set(credential)!={'kind','secret_arn','version_id','json_key'} or
                credential['kind']!='secretsmanager' or not isinstance(credential['secret_arn'],str) or
                not re.fullmatch(r'arn:aws:secretsmanager:'+REGION+':'+ACCOUNT+r':secret:[A-Za-z0-9/_+=.@-]{1,512}',credential['secret_arn']) or
                not isinstance(credential['version_id'],str) or not re.fullmatch('[A-Za-z0-9-]{32,64}',credential['version_id']) or
                credential['json_key'] not in (None,'api_key')):
            raise ValueError('immutable credential route')
    context={'root':root,'role':role,'source_commit':source}
    if role=='builder':
        if doc['builder_response_base64'] is not None or doc['candidate_commit'] is not None:raise ValueError('builder context')
    else:
        encoded=doc['builder_response_base64']
        if not isinstance(encoded,str) or len(encoded)>44000:raise ValueError('review material')
        context.update(builder_response=base64.b64decode(encoded,validate=True),candidate_commit=doc['candidate_commit'])
    return doc,context,keys


def _aws_session(env):
    # No profiles, metadata lookup, or invocation-supplied credential sources.
    import boto3
    values=[env.get(k) for k in ('AWS_ACCESS_KEY_ID','AWS_SECRET_ACCESS_KEY','AWS_SESSION_TOKEN')]
    if any(not isinstance(v,str) or not v or len(v)>8192 for v in values):raise ValueError('temporary AWS credentials')
    return boto3.Session(aws_access_key_id=values[0],aws_secret_access_key=values[1],
        aws_session_token=values[2],region_name=REGION)


def _client(session, service):
    from botocore.config import Config
    if service not in ('dynamodb','secretsmanager'):raise ValueError('unsupported service')
    return session.client(service,region_name=REGION,endpoint_url='https://'+service+'.'+REGION+'.amazonaws.com',
        config=Config(retries={'total_max_attempts':1},connect_timeout=5,read_timeout=10,proxies={}))


def _credential(session, route):
    if route['kind']=='lambda_execution_role':return session.get_credentials().get_frozen_credentials()
    response=_client(session,'secretsmanager').get_secret_value(SecretId=route['secret_arn'],VersionId=route['version_id'])
    if response.get('ARN')!=route['secret_arn'] or response.get('VersionId')!=route['version_id']:raise ValueError('secret identity')
    value=response.get('SecretString')
    if not isinstance(value,str) or not 0<len(value)<=8192:raise ValueError('secret format')
    if route['json_key'] is not None:
        document=json.loads(value,object_pairs_hook=_pairs)
        if not isinstance(document,dict) or set(document)!={'api_key'}:raise ValueError('secret schema')
        value=document['api_key']
    if not isinstance(value,str) or not 16<=len(value)<=512 or any(ord(c)<33 or ord(c)>126 for c in value):
        raise ValueError('secret key')
    return value


def dispatch(event, context, *, root, env, clock):
    # Keep disabled rejection before file reads, SDK imports and clients.
    if env.get('FACTORY_PILOT002_EXECUTION_ENABLED')!='true':raise StateError('Pilot 002 entry point disabled')
    try:
        role=env.get('FACTORY_PILOT002_ROLE')
        expected='arn:aws:lambda:'+REGION+':'+ACCOUNT+':function:tims-factory-pilot-002-'+str(role)
        if (context.invoked_function_arn!=expected or context.get_remaining_time_in_millis()<120000 or
                env.get('AWS_REGION')!=REGION or env.get('AWS_LAMBDA_FUNCTION_NAME')!='tims-factory-pilot-002-'+str(role)):
            raise ValueError('runtime identity or remaining time')
        if not isinstance(event,dict) or set(event)!={'kind','allowance'} or event['kind']!='pilot002_run_once' or len(canonical(event))>32768:
            raise ValueError('event schema')
        now=clock();doc,bound,keys=load_activation(root,env,now)
        adapter=Pilot002Adapter(**bound,qualification=doc['qualification'],clock=clock,enabled=False)
        # Verify before constructing any client; workflow verifies again before claim.
        request=request_bytes(root,role=role,builder_response=bound.get('builder_response'),candidate_commit=bound.get('candidate_commit'))
        verify(event['allowance'],**bound,request_bytes=request,pricing=adapter.pricing,
            readiness=doc['readiness'],trusted_keys=keys,now=now)
        session=_aws_session(env)
        store=Pilot002AttemptStore(_client(session,'dynamodb'))
        return run_bound_once(event['allowance'],**bound,qualification=doc['qualification'],readiness=doc['readiness'],
            trusted_keys=keys,store=store,load_credential=lambda:_credential(session,doc['credential']),clock=clock,enabled=True)
    except Exception as error:
        # Do not reflect event, provider errors, or credential material in logs.
        from .pilot002_workflow import Pilot002Stopped
        if type(error) is Pilot002Stopped:
            raise StateError(Pilot002Stopped.safe_message(error)) from None
        raise StateError('Pilot 002 entry point stopped; reconcile without retry') from None


def handler(event, context):
    return dispatch(event,context,root=Path(os.environ.get('LAMBDA_TASK_ROOT','/var/task')),
        env=os.environ,clock=lambda:datetime.now(timezone.utc))
