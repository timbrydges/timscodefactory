"""Disabled-by-default security role boundary with immutable deployment pins."""
import json
import os
import re
from pathlib import Path
from datetime import datetime, timezone

from factory_state.model import StateError
from factory_state.scope import canonical
from .pilot002_entrypoint import _read, _pairs, _aws_session, _credential
from .review_role_lambda import client, REGION, ACCOUNT
from .security_deployment import load_deployment, signer_loader
from .security_provider_scope import verify
from .security_role_runtime import BoundedSecurityRoleRuntime
from .security_composition import disabled_backend
from .worker import digest

NAME='tims-factory-review-security'


def load_allowance(root, env, *, material, keys, now):
    raw=_read(root,'SECURITY_ALLOWANCE.json',131072)
    if digest(raw)!=env.get('FACTORY_SECURITY_ALLOWANCE_DIGEST'):
        raise StateError('Security allowance differs from deployment pin')
    doc=json.loads(raw,object_pairs_hook=_pairs)
    if (type(doc) is not dict or canonical(doc)!=raw or
            set(doc)!={'allowance','pricing','readiness'}):
        raise StateError('Exact security allowance configuration required')
    verify(doc['allowance'],scope=material.prepared().scope,pricing=doc['pricing'],
        readiness=doc['readiness'],trusted_keys=keys(now),now=now)
    return doc


def dispatch(event, context, *, root, env, clock):
    if env.get('FACTORY_SECURITY_ENABLED')!='true':
        raise StateError('Security Lambda disabled')
    try:
        prefix=f'arn:aws:lambda:{REGION}:{ACCOUNT}:function:{NAME}:'
        arn=context.invoked_function_arn
        if (type(arn) is not str or not arn.startswith(prefix) or
                not re.fullmatch('[1-9][0-9]*',arn[len(prefix):]) or
                env.get('AWS_REGION')!=REGION or env.get('AWS_LAMBDA_FUNCTION_NAME')!=NAME or
                context.get_remaining_time_in_millis()<150000):
            raise StateError('Exact security numeric version and runtime required')
        deployment=load_deployment(root,env,clock=clock);m=deployment.material
        BoundedSecurityRoleRuntime.validate_event(m.prepared(),event)
        keys=signer_loader(root,env);history=signer_loader(root,env,historical=True)
        doc=load_allowance(root,env,material=m,keys=keys,now=clock())
        session=_aws_session(env)
        sts=client(session,'sts');caller=sts.get_caller_identity()
        role_prefix=f'arn:aws:sts::{ACCOUNT}:assumed-role/{NAME}/'
        caller_arn=caller.get('Arn','')
        if (caller.get('Account')!=ACCOUNT or type(caller_arn) is not str or
                not caller_arn.startswith(role_prefix) or not caller_arn[len(role_prefix):] or
                '/' in caller_arn[len(role_prefix):]):
            raise StateError('Exact security execution custody required')
        from factory_state.dynamodb import DynamoDBStateStore
        from factory_state.dispatch import DynamoDBDispatchStore
        from .security_provider_claims import SecurityProviderClaims
        db=client(session,'dynamodb');table='tims-software-factory-state'
        backend=disabled_backend(material=m,qa_binding=deployment.qa_binding,
            qa_request=deployment.qa_request,envelope=doc['allowance'],pricing=doc['pricing'],
            readiness=doc['readiness'],states=DynamoDBStateStore(table,db),
            ledger=DynamoDBDispatchStore(table,db),claims=SecurityProviderClaims(db),
            key_loader=keys,historical_key_loader=history,clock=clock)
        # The backend claims the permanent send before invoking this loader.
        backend.load_credential=lambda:_credential(session,{'kind':'lambda_execution_role'})
        backend.enabled=True
        return BoundedSecurityRoleRuntime(backend=backend,kms=client(session,'kms'),sts=sts,
            execution_table='tims-factory-role-executions',enabled=True).handle(event)
    except Exception:
        raise StateError('Security role stopped; reconcile permanent claims before further action') from None


def handler(event, context):
    return dispatch(event,context,root=Path(os.environ.get('LAMBDA_TASK_ROOT','/var/task')),
        env=os.environ,clock=lambda:datetime.now(timezone.utc))
