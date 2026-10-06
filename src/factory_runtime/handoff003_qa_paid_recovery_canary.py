"""Inert recovery permission proof; impossible predicates cannot create claims."""
import json,os,re
from pathlib import Path
from .handoff003_qa_paid_recovery_entrypoint import NAME,ARN,ENABLED
from .handoff003_qa_paid_recovery_authorization import TABLE,PK
from .handoff003_permission_canary import dependencies
from .handoff003_entrypoint import _client
from .handoff003_signing import assert_session
from .pilot002_entrypoint import _aws_session
from factory_state.model import StateError

MODE='FACTORY_HANDOFF003_QA_PAID_RECOVERY002_MODE'

def probe(db):
    targets=[(TABLE,PK,'ConditionalCheckFailedException'),(TABLE,PK+'#other','AccessDeniedException'),
        ('tims-factory-handoff-003-qa-recovery-001-attempts','HANDOFF#003#QA_RECOVERY#001','AccessDeniedException'),
        ('tims-factory-handoff-003-attempts','HANDOFF#003#TASK#authenticated-handoff-003#ROLE#qa','AccessDeniedException')]
    results=[]
    for table,key,expected in targets:
        try:db.put_item(TableName=table,Item={'PK':{'S':key}},ConditionExpression='attribute_exists(PK) AND attribute_not_exists(PK)')
        except Exception as error:
            code=getattr(error,'response',{}).get('Error',{}).get('Code')
            if code!=expected:raise StateError('Recovery permission proof inconclusive') from None
            results.append({'table':table,'key':key,'decision':code})
        else:raise StateError('Impossible claim predicate accepted')
    return results

def dispatch(event,context,*,root,env):
    arn=getattr(context,'invoked_function_arn','')
    if (env.get(ENABLED)!='false' or env.get(MODE)!='permissions_canary' or env.get('AWS_REGION')!='ca-central-1' or
        env.get('AWS_LAMBDA_FUNCTION_NAME')!=NAME or not isinstance(arn,str) or not arn.startswith(ARN) or
        not re.fullmatch('[1-9][0-9]*',arn[len(ARN):])):raise StateError('Disabled immutable recovery canary required')
    source=json.loads((root/'BUILD.json').read_bytes())['source_commit']
    if event!={'kind':'handoff003_qa_paid_recovery002_permissions_only','source_commit':source}:raise StateError('Recovery canary event differs')
    session=_aws_session(env);assert_session(_client(session,'sts'),'tims-factory-review-qa')
    rows=probe(_client(session,'dynamodb'));ready=dependencies(session,'qa')
    return {'status':'RECOVERY_PERMISSION_CANARY_VERIFIED','source_commit':source,'attempt_row_checks':rows,'dependencies':ready,
        'state_writes':0,'model_calls':0,'signing_calls':0,'execution_authorized':False}

def handler(event,context):
    try:return dispatch(event,context,root=Path(os.environ.get('LAMBDA_TASK_ROOT','/var/task')),env=os.environ)
    except Exception:raise StateError('Recovery canary failed without model call') from None
