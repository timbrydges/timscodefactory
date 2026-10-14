"""Default-disabled security-only controller; ticks carry no authority."""
import os
import re
from datetime import datetime, timezone
from pathlib import Path

from factory_state.model import StateError
from .pilot002_entrypoint import _aws_session
from .review_role_lambda import client, REGION, ACCOUNT
from .review_controller_lambda import runtime_client, NAME, EXECUTION_ROLE
from .security_deployment import load_deployment, signer_loader
from .security_role_lambda import load_allowance
from .security_provider_scope import verify
from .security_controller_config import load_controller_config
from .security_composition import disabled_backend
from .security_controller import BoundedSecurityController

EVENT={'factory_id':'tims-software-factory','task_id':'bounded-review-004','mode':'bounded-security'}


def dispatch(event, context, *, root, env, clock):
    if env.get('FACTORY_SECURITY_CONTROLLER_ENABLED')!='true':
        raise StateError('Security controller Lambda disabled')
    try:
        prefix=f'arn:aws:lambda:{REGION}:{ACCOUNT}:function:{NAME}:'
        arn=context.invoked_function_arn
        if (type(event) is not dict or event!=EVENT or type(arn) is not str or
                not arn.startswith(prefix) or not re.fullmatch('[1-9][0-9]*',arn[len(prefix):]) or
                env.get('AWS_REGION')!=REGION or env.get('AWS_LAMBDA_FUNCTION_NAME')!=NAME or
                context.get_remaining_time_in_millis()<240000):
            raise StateError('Exact security tick and numeric controller version required')
        deployment=load_deployment(root,env,clock=clock);m=deployment.material
        keys=signer_loader(root,env);history=signer_loader(root,env,historical=True)
        now=clock();doc=load_allowance(root,env,material=m,keys=keys,now=now)
        grant=verify(doc['allowance'],scope=m.prepared().scope,pricing=doc['pricing'],
            readiness=doc['readiness'],trusted_keys=keys(now),now=now)
        config=load_controller_config(root,env,deployment=deployment,grant=grant,now=now)
        session=_aws_session(env);caller=client(session,'sts').get_caller_identity()
        role_prefix=f'arn:aws:sts::{ACCOUNT}:assumed-role/{EXECUTION_ROLE}/'
        caller_arn=caller.get('Arn','')
        if (caller.get('Account')!=ACCOUNT or type(caller_arn) is not str or
                not caller_arn.startswith(role_prefix) or not caller_arn[len(role_prefix):] or
                '/' in caller_arn[len(role_prefix):]):
            raise StateError('Exact controller execution custody required')
        from factory_state.dynamodb import DynamoDBStateStore
        from factory_state.dispatch import DynamoDBDispatchStore
        from .security_provider_claims import SecurityProviderClaims
        db=client(session,'dynamodb');table='tims-software-factory-state'
        guard=disabled_backend(material=m,qa_binding=deployment.qa_binding,
            qa_request=deployment.qa_request,envelope=doc['allowance'],pricing=doc['pricing'],
            readiness=doc['readiness'],states=DynamoDBStateStore(table,db),
            ledger=DynamoDBDispatchStore(table,db),claims=SecurityProviderClaims(db),
            key_loader=keys,historical_key_loader=history,clock=clock)
        guard.enabled=True  # Credential loader stays absent in the controller.
        controller=BoundedSecurityController(activation=config.activation,
            deployed_commit=m.binding.qa.source_commit,guard=guard,prerequisites=guard.verify_prerequisites,
            lambda_api=runtime_client(session,'lambda'),s3=runtime_client(session,'s3'),
            function_arn=config.function_arn,job_versions={'SECURITY_REVIEW':config.job_version},enabled=True)
        return controller.tick(EVENT['factory_id'],EVENT['task_id'])
    except Exception:
        raise StateError('Security controller stopped; reconcile retained dispatch and claims before further action') from None


def handler(event, context):
    return dispatch(event,context,root=Path(os.environ.get('LAMBDA_TASK_ROOT','/var/task')),
        env=os.environ,clock=lambda:datetime.now(timezone.utc))
