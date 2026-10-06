"""Disabled bounded controller; configuration and authority never come from ticks."""
import json
import os
import re
from datetime import datetime, timezone, timedelta
from pathlib import Path

from factory_state.model import StateError
from factory_state.signers import load_trusted_signers
from .pilot002_entrypoint import _read, _pairs, _aws_session
from .review_role_lambda import client, ACCOUNT, REGION
from .review_material import PinnedReviewMaterial
from .review_provider_scope import verify, PROVIDERS, FACTORY, TASK
from .review_controller import BoundedReviewController, ROLES
from .acceptance_jobs import PinnedJobVersion
from .autonomy import AutonomyActivation
from .cloud_roles import FUNCTION
from .worker import digest

NAME='tims-software-factory-autonomy-controller'
EXECUTION_ROLE='tims-software-factory-autonomy-controller-disabled'
EVENT={'factory_id':FACTORY,'task_id':TASK,'mode':'bounded-review'}


def load_deployment(root, env, *, clock):
    build=json.loads(_read(root,'BUILD.json',1024),object_pairs_hook=_pairs)
    if type(build)is not dict or set(build)!={'source_commit'}:
        raise StateError('exact controller source required')
    material=PinnedReviewMaterial.load(_read(root,'REVIEW_MATERIAL.json',196608),
        expected_digest=env.get('FACTORY_BOUNDED_REVIEW_MATERIAL_DIGEST'),
        deployed_commit=build['source_commit'],clock=clock)
    raw=_read(root,'REVIEW_CONTROLLER.json',131072)
    if digest(raw)!=env.get('FACTORY_BOUNDED_REVIEW_CONTROLLER_DIGEST'):
        raise StateError('controller configuration differs from deployment pin')
    doc=json.loads(raw,object_pairs_hook=_pairs)
    if (type(doc)is not dict or set(doc)!={'activation','function_arns','job_versions','providers'} or
            any(type(doc[k])is not dict for k in doc)):
        raise StateError('exact controller configuration required')
    a=doc['activation']
    if set(a)!=set(AutonomyActivation.__dataclass_fields__):
        raise StateError('exact activation fields required')
    activation=AutonomyActivation(**{**a,'starts_at':datetime.fromisoformat(a['starts_at']),
        'expires_at':datetime.fromisoformat(a['expires_at'])})
    now=clock();activation.validate(now)
    if ((activation.activation_id,activation.factory_id,activation.task_id,
            activation.source_commit,activation.contract_digest)!=
            (TASK,FACTORY,TASK,material.source_commit,digest(material.contract_bytes)) or
            activation.expires_at-activation.starts_at>timedelta(hours=1)):
        raise StateError('controller activation differs from bounded deployment')
    if (set(doc['function_arns'])!=set(PROVIDERS) or set(doc['providers'])!=set(PROVIDERS) or
            set(doc['job_versions'])!=set(ROLES)):
        raise StateError('exact three role routes and job versions required')
    keys=lambda at:load_trusted_signers(root/'factory/profiles/scope-signers.json',now=at)
    for role in PROVIDERS:
        arn=doc['function_arns'][role]
        match=FUNCTION.fullmatch(arn) if type(arn)is str else None
        p=doc['providers'][role]
        if match is None or match.group(1)!=role:
            raise StateError('immutable role function route differs')
        if type(p)is not dict or set(p)!={'allowance','pricing','readiness'}:
            raise StateError('controller provider authorization fields differ')
        grant=verify(p['allowance'],scope=material.prepared(role).scope,pricing=p['pricing'],
            readiness=p['readiness'],trusted_keys=keys(now),now=now)
        if activation.expires_at.timestamp()>grant.expires_at:
            raise StateError('controller window exceeds provider allowance')
    versions={stage:PinnedJobVersion(**pin) for stage,pin in doc['job_versions'].items()}
    return material,activation,doc,versions,keys


def runtime_client(session, service):
    from botocore.config import Config
    if service not in ('s3','lambda'):raise StateError('unexpected controller client')
    return session.client(service,region_name=REGION,endpoint_url=f'https://{service}.{REGION}.amazonaws.com',
        config=Config(retries={'total_max_attempts':1},connect_timeout=5,
            read_timeout=185 if service=='lambda' else 10,proxies={}))


def dispatch(event, context, *, root, env, clock):
    if env.get('FACTORY_BOUNDED_CONTROLLER_ENABLED')!='true':
        raise StateError('bounded controller Lambda disabled')
    try:
        prefix=f'arn:aws:lambda:{REGION}:{ACCOUNT}:function:{NAME}:'
        arn=context.invoked_function_arn
        if (type(event)is not dict or event!=EVENT or type(arn)is not str or not arn.startswith(prefix) or
                not re.fullmatch('[1-9][0-9]*',arn[len(prefix):]) or env.get('AWS_REGION')!=REGION or
                env.get('AWS_LAMBDA_FUNCTION_NAME')!=NAME or context.get_remaining_time_in_millis()<240000):
            raise StateError('exact bounded controller event and numeric version required')
        material,activation,doc,versions,keys=load_deployment(root,env,clock=clock)
        session=_aws_session(env)
        caller=client(session,'sts').get_caller_identity()
        role_prefix=f'arn:aws:sts::{ACCOUNT}:assumed-role/{EXECUTION_ROLE}/'
        caller_arn=caller.get('Arn','')
        if (caller.get('Account')!=ACCOUNT or not caller_arn.startswith(role_prefix) or
                not caller_arn[len(role_prefix):] or '/' in caller_arn[len(role_prefix):]):
            raise StateError('exact isolated controller execution role required')
        from factory_state.dynamodb import DynamoDBStateStore
        from factory_state.dispatch import DynamoDBDispatchStore
        from .review_provider_backend import ReviewProviderBackend
        from .review_provider_claims import ReviewProviderClaims
        db=client(session,'dynamodb');table='tims-software-factory-state'
        states=DynamoDBStateStore(table,db);ledger=DynamoDBDispatchStore(table,db)
        guards={role:ReviewProviderBackend(prepared=material.prepared(role),
            envelope=p['allowance'],pricing=p['pricing'],readiness=p['readiness'],
            states=states,ledger=ledger,claims=ReviewProviderClaims(db),key_loader=keys,clock=clock,
            test_evidence=material.evidence('qa' if role=='qa' else 'inspector',clock=clock),
            enabled=True) for role,p in doc['providers'].items()}
        service=BoundedReviewController(activation=activation,deployed_commit=material.source_commit,
            states=states,ledger=ledger,key_loader=keys,lambda_api=runtime_client(session,'lambda'),
            s3=runtime_client(session,'s3'),function_arns=doc['function_arns'],guards=guards,
            job_versions=versions,inspector_binding=material.binding('inspector'),qa_binding=material.binding('qa'),
            builder_input_digest=material.prepared('builder').scope.request.input_digest,
            proof_bytes=material.proof_bytes,candidate_files=material.files(),test_count=17,clock=clock,enabled=True)
        return service.tick(FACTORY,TASK)
    except Exception:
        raise StateError('bounded controller stopped; reconcile permanent claims before further action') from None


def handler(event, context):
    return dispatch(event,context,root=Path(os.environ.get('LAMBDA_TASK_ROOT','/var/task')),
        env=os.environ,clock=lambda:datetime.now(timezone.utc))
