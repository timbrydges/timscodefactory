"""Disabled observer with exact read-only attempt access and no worker invocation."""
from prepare_handoff002_foundation import render as foundation,ACCOUNT,REGION
from factory_runtime.handoff002_attempts import TABLE,key,ROLES
from factory_runtime.handoff002_observer import NAME
from factory_state.model import StateError

STACK=NAME+'-disabled'


def render(*,source_commit,code):
    foundation(source_commit=source_commit,code=code) # Validate immutable source/package.
    arn=f'arn:aws:lambda:{REGION}:{ACCOUNT}:function:{NAME}'
    condition={'ArnEquals':{'lambda:SourceFunctionArn':arn}}
    return {'AWSTemplateFormatVersion':'2010-09-09','Resources':{
        'Logs':{'Type':'AWS::Logs::LogGroup','DeletionPolicy':'Retain','UpdateReplacePolicy':'Retain',
            'Properties':{'LogGroupName':'/aws/lambda/'+NAME,'RetentionInDays':7}},
        'Role':{'Type':'AWS::IAM::Role','Properties':{'RoleName':NAME,
            'AssumeRolePolicyDocument':{'Version':'2012-10-17','Statement':[{'Effect':'Allow',
                'Principal':{'Service':'lambda.amazonaws.com'},'Action':'sts:AssumeRole'}]},
            'Policies':[{'PolicyName':'observe-only','PolicyDocument':{'Version':'2012-10-17','Statement':[
                {'Effect':'Allow','Action':'dynamodb:GetItem','Resource':f'arn:aws:dynamodb:{REGION}:{ACCOUNT}:table/{TABLE}',
                 'Condition':{**condition,'ForAllValues:StringEquals':{'dynamodb:LeadingKeys':[key(r)['PK']['S'] for r in ROLES]}}},
                {'Effect':'Allow','Action':['logs:CreateLogStream','logs:PutLogEvents'],
                 'Resource':f'arn:aws:logs:{REGION}:{ACCOUNT}:log-group:/aws/lambda/{NAME}:*','Condition':condition}]}}]}},
        'Function':{'Type':'AWS::Lambda::Function','DependsOn':'Logs','Properties':{
            'FunctionName':NAME,'Runtime':'python3.12','Architectures':['x86_64'],'MemorySize':256,'Timeout':30,
            'Role':{'Fn::GetAtt':['Role','Arn']},'Handler':'factory_runtime.handoff002_observer.handler',
            'Code':code,'ReservedConcurrentExecutions':0,
            'Environment':{'Variables':{'FACTORY_HANDOFF002_OBSERVER_ENABLED':'false'}},
            'Tags':[{'Key':'SourceCommit','Value':source_commit}]}}}}


def validate_changes(template,preview,**args):
    if (template!=render(**args) or preview.get('Status')!='CREATE_COMPLETE' or
            preview.get('ExecutionStatus')!='AVAILABLE' or preview.get('NextToken') or preview.get('Parameters') or
            not str(preview.get('StackId','')).startswith(f'arn:aws:cloudformation:{REGION}:{ACCOUNT}:stack/{STACK}/')):
        raise StateError('Observer preview differs')
    changes=preview.get('Changes',[])
    if len(changes)!=3 or {x.get('ResourceChange',{}).get('LogicalResourceId') for x in changes}!=set(template['Resources']):
        raise StateError('Exactly three observer additions required')
    for x in changes:
        r=x['ResourceChange']
        if x.get('Type')!='Resource' or r.get('Action')!='Add' or r.get('ResourceType')!=template['Resources'][r['LogicalResourceId']]['Type']:
            raise StateError('Existing resources cannot change')
    return {'status':'VALIDATED_NOT_EXECUTED','provider_permissions':0,'worker_invoke_permissions':0}
