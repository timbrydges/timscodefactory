"""Disabled dispatcher foundation; immutable worker versions must be explicit."""
import copy
import re
from prepare_handoff004_foundation import render as foundation,ACCOUNT,REGION
from prepare_handoff002_dispatch_ledger import render as ledger
from factory_runtime.handoff004_dispatch import TABLE
from factory_runtime.handoff004_attempts import TABLE as ATTEMPTS,key,ROLES
from factory_runtime.handoff004_packets import TASK
from factory_runtime.handoff004_dispatcher import NAME
from factory_state.model import StateError

STACK=NAME+'-disabled'


def policy(versions):
    if type(versions)is not dict or not set(versions)<=set(ROLES):raise StateError('Exact role versions required')
    for role,arn in versions.items():
        prefix=f'arn:aws:lambda:{REGION}:{ACCOUNT}:function:tims-factory-handoff-004-{role}:'
        if not isinstance(arn,str) or not arn.startswith(prefix) or not re.fullmatch('[1-9][0-9]*',arn[len(prefix):]):
            raise StateError('Aliases and other worker versions are forbidden')
    condition={'ArnEquals':{'lambda:SourceFunctionArn':f'arn:aws:lambda:{REGION}:{ACCOUNT}:function:{NAME}'}}
    def row(actions,table,keys):
        return {'Effect':'Allow','Action':actions,'Resource':f'arn:aws:dynamodb:{REGION}:{ACCOUNT}:table/{table}',
            'Condition':{**condition,'ForAllValues:StringEquals':{'dynamodb:LeadingKeys':keys}}}
    statements=[row(['dynamodb:GetItem'],ATTEMPTS,[key(r)['PK']['S'] for r in ROLES]),
        row(['dynamodb:GetItem','dynamodb:PutItem','dynamodb:UpdateItem'],TABLE,
            ['HANDOFF#004#CONTROLLER#'+TASK+'#'+r for r in ROLES]),
        {'Effect':'Allow','Action':['logs:CreateLogStream','logs:PutLogEvents'],
         'Resource':f'arn:aws:logs:{REGION}:{ACCOUNT}:log-group:/aws/lambda/{NAME}:*','Condition':condition}]
    if versions:statements.append({'Effect':'Allow','Action':['lambda:GetFunctionConfiguration','lambda:InvokeFunction'],
        'Resource':[versions[r] for r in ROLES if r in versions],'Condition':condition})
    return {'Version':'2012-10-17','Statement':statements}


def render(*,source_commit,code):
    foundation(source_commit=source_commit,code=code)
    table=copy.deepcopy(ledger()['Resources']['DispatchLedger']);table['Properties']['TableName']=TABLE
    return {'AWSTemplateFormatVersion':'2010-09-09','Resources':{
        'DispatchLedger':table,
        'Logs':{'Type':'AWS::Logs::LogGroup','DeletionPolicy':'Retain','UpdateReplacePolicy':'Retain',
            'Properties':{'LogGroupName':'/aws/lambda/'+NAME,'RetentionInDays':7}},
        'Role':{'Type':'AWS::IAM::Role','Properties':{'RoleName':NAME,
            'AssumeRolePolicyDocument':{'Version':'2012-10-17','Statement':[{'Effect':'Allow',
                'Principal':{'Service':'lambda.amazonaws.com'},'Action':'sts:AssumeRole'}]},
            'Policies':[{'PolicyName':'exact-dispatch','PolicyDocument':policy({})}]}},
        'Function':{'Type':'AWS::Lambda::Function','DependsOn':'Logs','Properties':{
            'FunctionName':NAME,'Runtime':'python3.12','Architectures':['x86_64'],'MemorySize':256,'Timeout':240,
            'Role':{'Fn::GetAtt':['Role','Arn']},'Handler':'factory_runtime.handoff004_dispatcher.handler',
            'Code':code,'ReservedConcurrentExecutions':0,
            'Environment':{'Variables':{'FACTORY_HANDOFF004_DISPATCH_ENABLED':'false'}},
            'Tags':[{'Key':'SourceCommit','Value':source_commit}]}}}}


def validate_changes(template,preview,**args):
    if (template!=render(**args) or preview.get('Status')!='CREATE_COMPLETE' or
            preview.get('ExecutionStatus')!='AVAILABLE' or preview.get('NextToken') or preview.get('Parameters') or
            not str(preview.get('StackId','')).startswith(f'arn:aws:cloudformation:{REGION}:{ACCOUNT}:stack/{STACK}/')):
        raise StateError('Dispatcher preview differs')
    changes=preview.get('Changes',[])
    if len(changes)!=4 or {x.get('ResourceChange',{}).get('LogicalResourceId') for x in changes}!=set(template['Resources']):
        raise StateError('Exactly four dispatcher additions required')
    for x in changes:
        r=x['ResourceChange']
        if x.get('Type')!='Resource' or r.get('Action')!='Add' or r.get('ResourceType')!=template['Resources'][r['LogicalResourceId']]['Type']:
            raise StateError('Existing resources cannot change')
    return {'status':'VALIDATED_NOT_EXECUTED','provider_permissions':0,'worker_invoke_permissions':0}
