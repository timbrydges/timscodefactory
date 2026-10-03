"""Prepare/validate a disabled, logging-only three-role runtime. Never deploys."""
import copy
import json
import re
import sys
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'src'))
from factory_state.model import StateError

STACK='tims-factory-pilot-002-runtime-disabled'
ACCOUNT='666730517561'
REGION='ca-central-1'
ROLES=('builder','inspector','qa')


def render(*, source_commit, code):
    if (not isinstance(source_commit,str) or not re.fullmatch('[0-9a-f]{40}',source_commit) or
            not isinstance(code,dict) or set(code)!={'S3Bucket','S3Key','S3ObjectVersion'} or
            any(not isinstance(v,str) or not v or len(v)>1024 for v in code.values()) or
            code['S3ObjectVersion']=='null'):
        raise StateError('Pilot 002 deployment requires source commit and immutable S3 object version')
    resources={}
    for role in ROLES:
        prefix=role.title();name='tims-factory-pilot-002-'+role
        resources[prefix+'Logs']={'Type':'AWS::Logs::LogGroup','DeletionPolicy':'Retain',
            'UpdateReplacePolicy':'Retain','Properties':{'LogGroupName':'/aws/lambda/'+name,'RetentionInDays':7}}
        resources[prefix+'Role']={'Type':'AWS::IAM::Role','Properties':{
            'RoleName':name+'-disabled','AssumeRolePolicyDocument':{'Version':'2012-10-17','Statement':[{
                'Effect':'Allow','Principal':{'Service':'lambda.amazonaws.com'},'Action':'sts:AssumeRole'}]},
            'Policies':[{'PolicyName':'own-probe-logs-only','PolicyDocument':{'Version':'2012-10-17','Statement':[{
                'Effect':'Allow','Action':['logs:CreateLogStream','logs:PutLogEvents'],
                'Resource':f'arn:aws:logs:{REGION}:{ACCOUNT}:log-group:/aws/lambda/{name}:*'}]}}]}}
        resources[prefix+'Function']={'Type':'AWS::Lambda::Function','DependsOn':prefix+'Logs','Properties':{
            'FunctionName':name,'Description':'Pilot 002 disabled package probe; no active dispatch',
            'Runtime':'python3.12','Architectures':['x86_64'],'MemorySize':256,'Timeout':30,
            'Handler':'factory_runtime.pilot002_runtime_probe.handler',
            'Role':{'Fn::GetAtt':[prefix+'Role','Arn']},'Code':copy.deepcopy(code),
            'ReservedConcurrentExecutions':0,'Environment':{'Variables':{
                'FACTORY_PILOT002_EXECUTION_ENABLED':'false','FACTORY_PILOT002_ROLE':role}},
            'Tags':[{'Key':'SourceCommit','Value':source_commit},{'Key':'Purpose','Value':'disabled-package-probe'}]}}
    return {'AWSTemplateFormatVersion':'2010-09-09',
        'Description':'Pilot 002 disabled runtime foundation; no model, secret or database access.',
        'Resources':resources}


def validate_changes(template, change_set, *, source_commit, code):
    expected=render(source_commit=source_commit,code=code)
    prefix=f'arn:aws:cloudformation:{REGION}:{ACCOUNT}:stack/{STACK}/'
    if (template!=expected or change_set.get('Status')!='CREATE_COMPLETE' or
            change_set.get('ExecutionStatus')!='AVAILABLE' or change_set.get('NextToken') or
            change_set.get('Parameters') or not str(change_set.get('StackId','')).startswith(prefix)):
        raise StateError('Pilot 002 runtime preview differs or is incomplete')
    changes=change_set.get('Changes',[])
    names=[item.get('ResourceChange',{}).get('LogicalResourceId') for item in changes]
    if len(names)!=9 or set(names)!=set(expected['Resources']):
        raise StateError('Pilot 002 runtime preview must contain exactly nine new resources')
    for item in changes:
        resource=item['ResourceChange']
        if (item.get('Type')!='Resource' or resource.get('Action')!='Add' or
                resource.get('ResourceType')!=expected['Resources'][resource['LogicalResourceId']]['Type']):
            raise StateError('Pilot 002 runtime preview must only add disabled foundation resources')
    return {'status':'VALIDATED_NOT_EXECUTED','new_functions':3,'new_logging_only_roles':3,
        'new_log_groups':3,'reserved_concurrency':0,'model_calls':0,'source_commit':source_commit}


if __name__=='__main__':
    source_commit=sys.argv[1];code=json.loads(Path(sys.argv[2]).read_bytes())
    with Path(sys.argv[3]).open('x',encoding='utf-8') as stream:
        json.dump(render(source_commit=source_commit,code=code),stream,indent=2)
    print('PREPARED_NOT_AUTHORIZED: three disabled functions, logging-only roles and log groups')
