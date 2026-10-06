"""Disabled-by-default immutable-version entrypoint for bounded-review-002 only."""
import json
import os
import re
from pathlib import Path
from datetime import datetime, timezone

from factory_state.model import StateError
from factory_state.signers import load_trusted_signers
from .pilot002_entrypoint import _read, _pairs, _aws_session, _credential
from .review_material import PinnedReviewMaterial
from .review_provider_scope import verify, PROVIDERS
from .review_role_runtime import BoundedReviewRoleRuntime
from .review_provider_backend import BoundedProviderFailure
from .worker import digest

REGION='ca-central-1'
ACCOUNT='666730517561'
EXECUTION_ROLES={'builder':'tims-factory-executor-builder',
                 'inspector':'tims-factory-executor-inspector','qa':'tims-factory-review-qa'}
SECRETS={'builder':'arn:aws:secretsmanager:ca-central-1:666730517561:secret:tims-software-factory/provider/openai/acceptance-WE57Tw',
         'qa':'arn:aws:secretsmanager:ca-central-1:666730517561:secret:tims-software-factory/provider/google/qa-rYGeOE'}


def load_deployment(root, env, *, clock):
    role=env.get('FACTORY_BOUNDED_REVIEW_ROLE')
    if role not in PROVIDERS:raise StateError('exact bounded role required')
    build=json.loads(_read(root,'BUILD.json',1024),object_pairs_hook=_pairs)
    if set(build)!={'source_commit'}:raise StateError('exact build source required')
    material=PinnedReviewMaterial.load(_read(root,'REVIEW_MATERIAL.json',196608),
        expected_digest=env.get('FACTORY_BOUNDED_REVIEW_MATERIAL_DIGEST'),
        deployed_commit=build['source_commit'],clock=clock)
    raw=_read(root,'REVIEW_ROLE.json',131072)
    if digest(raw)!=env.get('FACTORY_BOUNDED_REVIEW_ROLE_DIGEST'):
        raise StateError('role authorization differs from deployment pin')
    doc=json.loads(raw,object_pairs_hook=_pairs)
    if (type(doc)is not dict or set(doc)!={'role','allowance','pricing','readiness','credential'} or
            doc['role']!=role):raise StateError('exact role authorization required')
    route=doc['credential']
    if role=='inspector':
        if route!={'kind':'lambda_execution_role'}:raise StateError('Inspector credential route differs')
    elif (type(route)is not dict or set(route)!={'kind','secret_arn','version_id','json_key'} or
            route['kind']!='secretsmanager' or route['secret_arn']!=SECRETS[role] or
            type(route['version_id'])is not str or not re.fullmatch('[A-Za-z0-9-]{32,64}',route['version_id']) or
            route['json_key'] not in (None,'api_key')):
        raise StateError('exact versioned provider secret required')
    keys=lambda now:load_trusted_signers(root/'factory/profiles/scope-signers.json',now=now)
    verify(doc['allowance'],scope=material.prepared(role).scope,pricing=doc['pricing'],
           readiness=doc['readiness'],trusted_keys=keys(clock()),now=clock())
    return role,material,doc,keys


def client(session, service):
    from botocore.config import Config
    if service not in ('sts','kms','dynamodb'):raise StateError('unexpected runtime client')
    return session.client(service,region_name=REGION,endpoint_url=f'https://{service}.{REGION}.amazonaws.com',
        config=Config(retries={'total_max_attempts':1},connect_timeout=5,read_timeout=10,proxies={}))


def dispatch(event, context, *, root, env, clock):
    if env.get('FACTORY_BOUNDED_REVIEW_ENABLED')!='true':
        raise StateError('bounded role Lambda disabled')
    try:
        role=env.get('FACTORY_BOUNDED_REVIEW_ROLE')
        name='tims-factory-'+str(role)
        prefix=f'arn:aws:lambda:{REGION}:{ACCOUNT}:function:{name}:'
        arn=context.invoked_function_arn
        if (role not in PROVIDERS or type(arn)is not str or not arn.startswith(prefix) or
                not re.fullmatch('[1-9][0-9]*',arn[len(prefix):]) or
                env.get('AWS_REGION')!=REGION or env.get('AWS_LAMBDA_FUNCTION_NAME')!=name or
                context.get_remaining_time_in_millis()<150000):
            raise StateError('exact numeric role version and execution time required')
        role,material,doc,keys=load_deployment(root,env,clock=clock)
        prepared=material.prepared(role)
        BoundedReviewRoleRuntime.validate_event(prepared,event)
        session=_aws_session(env)
        caller=client(session,'sts').get_caller_identity()
        role_prefix=f'arn:aws:sts::{ACCOUNT}:assumed-role/{EXECUTION_ROLES[role]}/'
        caller_arn=caller.get('Arn','')
        if (caller.get('Account')!=ACCOUNT or not caller_arn.startswith(role_prefix) or
                not caller_arn[len(role_prefix):] or '/' in caller_arn[len(role_prefix):]):
            raise StateError('isolated execution role required')
        signing=session
        if role!='qa':
            credentials=client(session,'sts').assume_role(
                RoleArn=f'arn:aws:iam::{ACCOUNT}:role/tims-factory-signing-{role}',
                RoleSessionName='bounded-review-002-'+role,DurationSeconds=900)['Credentials']
            import boto3
            signing=boto3.Session(aws_access_key_id=credentials['AccessKeyId'],
                aws_secret_access_key=credentials['SecretAccessKey'],aws_session_token=credentials['SessionToken'],
                region_name=REGION)
        from factory_state.dynamodb import DynamoDBStateStore
        from factory_state.dispatch import DynamoDBDispatchStore
        from .review_provider_backend import ReviewProviderBackend
        from .review_provider_claims import ReviewProviderClaims
        db=client(session,'dynamodb');table='tims-software-factory-state'
        backend=ReviewProviderBackend(prepared=prepared,envelope=doc['allowance'],pricing=doc['pricing'],
            readiness=doc['readiness'],states=DynamoDBStateStore(table,db),ledger=DynamoDBDispatchStore(table,db),
            claims=ReviewProviderClaims(db),key_loader=keys,clock=clock,
            test_evidence=material.evidence('qa' if role=='qa' else 'inspector',clock=clock),
            load_credential=lambda:_credential(session,doc['credential']),enabled=True)
        return BoundedReviewRoleRuntime(backend=backend,kms=client(signing,'kms'),sts=client(signing,'sts'),
            execution_table='tims-factory-role-executions',enabled=True).handle(event)
    except BoundedProviderFailure as error:
        # Reconstruct rather than forwarding mutable exception text or arguments.
        from .pilot002_transport import ProviderHTTPStatusError, ProviderTimeoutError
        from .review_provider_protocol import ResponseValidationFailure
        cause = ProviderHTTPStatusError(error.http_status) if error.http_status is not None else (
            ProviderTimeoutError() if error.category == 'timeout' else None)
        if error.phase == 'response validation':
            cause = ResponseValidationFailure(error.category)
        raise BoundedProviderFailure(error.phase, cause) from None
    except Exception:
        raise StateError('bounded role stopped; reconcile permanent claims before any further action') from None


def handler(event, context):
    return dispatch(event,context,root=Path(os.environ.get('LAMBDA_TASK_ROOT','/var/task')),
                    env=os.environ,clock=lambda:datetime.now(timezone.utc))
