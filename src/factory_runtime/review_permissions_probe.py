"""Explicit read-only pre-deployment probe; never a review or spending authority."""
import json
import os
import re
from pathlib import Path

from factory_state.model import StateError, COMMIT_SHA
from .pilot002_entrypoint import _read, _pairs, _aws_session
from .review_role_lambda import client, ACCOUNT, REGION, EXECUTION_ROLES
from .review_controller_lambda import NAME, EXECUTION_ROLE
from .cloud_roles import ROLE_IDENTITIES
from .review_provider_scope import FACTORY, TASK
from .review_provider_claims import TABLE


def dispatch(event, context, *, root, env):
    if env.get('FACTORY_REVIEW_PERMISSION_PROBE_ENABLED')!='true':
        raise StateError('bounded permission probe disabled')
    try:
        if any(env.get(k)!='false' for k in ('FACTORY_BOUNDED_REVIEW_ENABLED','FACTORY_BOUNDED_CONTROLLER_ENABLED')):
            raise StateError('paid execution must be explicitly disabled')
        role=env.get('FACTORY_REVIEW_PERMISSION_PROBE_ROLE')
        if role not in (*EXECUTION_ROLES,'controller'):raise StateError('exact probe role required')
        name=NAME if role=='controller' else 'tims-factory-'+role
        execution=EXECUTION_ROLE if role=='controller' else EXECUTION_ROLES[role]
        build=json.loads(_read(root,'BUILD.json',1024),object_pairs_hook=_pairs)
        source=build.get('source_commit')
        if set(build)!={'source_commit'} or type(source)is not str or not COMMIT_SHA.fullmatch(source):
            raise StateError('exact probe source required')
        if (type(event)is not dict or set(event)!={'kind','source_commit','nonce'} or
                event['kind']!='bounded_review_data_read_probe' or event['source_commit']!=source or
                type(event['nonce'])is not str or not re.fullmatch('[0-9a-f]{64}',event['nonce'])):
            raise StateError('exact deployment probe event required')
        arn=context.invoked_function_arn;prefix=f'arn:aws:lambda:{REGION}:{ACCOUNT}:function:{name}:'
        if (type(arn)is not str or not arn.startswith(prefix) or not re.fullmatch('[1-9][0-9]*',arn[len(prefix):]) or
                env.get('AWS_REGION')!=REGION or env.get('AWS_LAMBDA_FUNCTION_NAME')!=name):
            raise StateError('probe requires exact numeric function version')
        session=_aws_session(env);caller=client(session,'sts').get_caller_identity()
        expected=f'arn:aws:sts::{ACCOUNT}:assumed-role/{execution}/';actual=caller.get('Arn','')
        if (caller.get('Account')!=ACCOUNT or not actual.startswith(expected) or
                not actual[len(expected):] or '/' in actual[len(expected):]):
            raise StateError('probe execution role differs')
        db=client(session,'dynamodb');reads=[]
        task=f'FACTORY#{FACTORY}#TASK#{TASK}'
        targets=[('tims-software-factory-state',{'PK':{'S':task},'SK':{'S':'STATE'}}),
                 ('tims-software-factory-state',{'PK':{'S':f'FACTORY#{FACTORY}#TASK#SCOPE#OBJECTIVE#{TASK}'},
                                                'SK':{'S':'CAPABILITY#bounded-review'}})]
        providers=tuple(EXECUTION_ROLES) if role=='controller' else (role,)
        targets.extend((TABLE,{'PK':{'S':'BOUNDED_REVIEW#002#ROLE#'+r}}) for r in providers)
        if role!='controller':
            targets.append(('tims-factory-role-executions',
                {'PK':{'S':f'ROLE#{ROLE_IDENTITIES[role]}#{task}'},'SK':{'S':f'EXECUTION#bounded-review-002-{role}'}}))
        for table,key in targets:
            response=db.get_item(TableName=table,Key=key,ConsistentRead=True)
            if response.get('Item'):raise StateError('fresh task/scope/claim already exists; reconcile')
            reads.append({'table':table,'key':key,'absent':True})
        # No existing task contents are returned, even if the denial unexpectedly fails.
        try:
            db.get_item(TableName=TABLE,Key={'PK':{'S':'BOUNDED_REVIEW#002#ROLE#unapproved'}},ConsistentRead=True)
        except Exception as error:
            if getattr(error,'response',{}).get('Error',{}).get('Code')!='AccessDeniedException':raise
        else:raise StateError('probe read outside approved claims was not denied')
        return {'status':'READ_ONLY_DATA_ACCESS_VERIFIED','source_commit':source,'role':role,
            'function_arn':arn,'nonce':event['nonce'],'reads':reads,'unapproved_claim_read_denied':True,
            'writes':0,'provider_calls':0,'signatures':0,'gate_authority':False}
    except Exception:
        raise StateError('bounded data permission probe failed; no writes or provider calls attempted') from None


def handler(event, context):
    return dispatch(event,context,root=Path(os.environ.get('LAMBDA_TASK_ROOT','/var/task')),env=os.environ)
