"""Render only a disabled recovery worker and its separate permanent claim table."""
import copy
from prepare_handoff003_foundation import render as old_foundation,ACCOUNT,REGION
from prepare_handoff003_access import policy as old_policy
from factory_runtime.handoff003_qa_recovery_authorization import TABLE,PK
from factory_runtime.handoff003_qa_recovery_entrypoint import NAME,ENABLED
from factory_state.model import StateError

STACK=NAME+'-disabled'

def policy():
    result=old_policy('qa')
    row=result['Statement'][0]
    row['Resource']=f'arn:aws:dynamodb:{REGION}:{ACCOUNT}:table/{TABLE}'
    row['Condition']['ForAllValues:StringEquals']['dynamodb:LeadingKeys']=[PK]
    for statement in result['Statement']:
        if statement['Action']!='kms:Decrypt':
            statement['Condition']['ArnEquals']['lambda:SourceFunctionArn']=f'arn:aws:lambda:{REGION}:{ACCOUNT}:function:{NAME}'
        if statement['Sid']=='OwnHandoffLogs':
            statement['Resource']=f'arn:aws:logs:{REGION}:{ACCOUNT}:log-group:/aws/lambda/{NAME}:*'
    return result

def render(*,source_commit,code):
    old=old_foundation(source_commit=source_commit,code=code)['Resources']
    resources={name:copy.deepcopy(old[name]) for name in ('Attempts','QaLogs','QaFunction')}
    resources['Attempts']['Properties']['TableName']=TABLE
    resources['QaLogs']['Properties']['LogGroupName']='/aws/lambda/'+NAME
    function=resources['QaFunction']['Properties']
    function.update(FunctionName=NAME,Timeout=240,Handler='factory_runtime.handoff003_qa_recovery_entrypoint.handler',
        Description='Disabled separate QA recovery; no fresh signed allowance installed',Environment={'Variables':{ENABLED:'false'}})
    resources['QaAccess']={'Type':'AWS::IAM::Policy','Properties':{'PolicyName':'handoff003-qa-recovery001-own-attempt',
        'Roles':['tims-factory-review-qa'],'PolicyDocument':policy()}}
    return {'AWSTemplateFormatVersion':'2010-09-09','Description':'Separate disabled QA recovery with permanent claims; no schedules or task writes.', 'Resources':resources}

def validate_changes(template,change_set,*,source_commit,code):
    expected=render(source_commit=source_commit,code=code)
    if (template!=expected or change_set.get('Status')!='CREATE_COMPLETE' or change_set.get('ExecutionStatus')!='AVAILABLE'
        or change_set.get('NextToken') or change_set.get('Parameters') or not str(change_set.get('StackId','')).startswith(
            f'arn:aws:cloudformation:{REGION}:{ACCOUNT}:stack/{STACK}/')):
        raise StateError('Recovery foundation preview differs or is incomplete')
    changes=change_set.get('Changes',[])
    names=[v.get('ResourceChange',{}).get('LogicalResourceId') for v in changes]
    if len(names)!=4 or set(names)!=set(expected['Resources']):raise StateError('Exactly four new recovery resources required')
    for item in changes:
        value=item['ResourceChange']
        if (item.get('Type')!='Resource' or value.get('Action')!='Add' or
            value.get('ResourceType')!=expected['Resources'][value['LogicalResourceId']]['Type']):
            raise StateError('Recovery foundation cannot modify existing resources')
    return {'status':'VALIDATED_NOT_EXECUTED','new_functions':1,'new_attempt_tables':1,'new_policies':1,'reserved_concurrency':0,'model_calls':0}
