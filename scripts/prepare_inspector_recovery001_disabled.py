"""Offline isolated disabled-function template. No uploads, AWS clients or execution."""
import base64
import re
import sys
from pathlib import Path

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'src'))
from build_inspector_recovery001_package import HANDLER
from factory_state.model import StateError

STACK='tims-factory-inspector-recovery-001-disabled'
FUNCTION='tims-factory-inspector-recovery-001'
ROLE='tims-factory-inspector-recovery-001-disabled'
BUCKET='tims-software-factory-666730517561-ca-central-1'
LOG='/aws/lambda/'+FUNCTION


def render(package,code):
    expected={'source_commit','sha256','code_sha256','zip_bytes','handler','execution_enabled',
        'activation_included','signed_allowance_included','model_calls'}
    if (type(package) is not dict or set(package)!=expected or
            not isinstance(package['source_commit'],str) or not re.fullmatch('[0-9a-f]{40}',package['source_commit']) or
            not isinstance(package['sha256'],str) or not re.fullmatch('[0-9a-f]{64}',package['sha256']) or
            package['code_sha256']!=base64.b64encode(bytes.fromhex(package['sha256'])).decode() or
            type(package['zip_bytes']) is not int or not 0<package['zip_bytes']<=5000000 or
            package['handler']!=HANDLER or package['execution_enabled'] is not False or
            package['activation_included'] is not False or package['signed_allowance_included'] is not False or
            type(package['model_calls']) is not int or package['model_calls']!=0):
        raise StateError('Recovery disabled package differs')
    if (type(code) is not dict or set(code)!={'S3Bucket','S3Key','S3ObjectVersion'} or
            code['S3Bucket']!=BUCKET or code['S3Key']!='inspector-recovery-001/runtime/'+package['source_commit']+'/'+package['sha256']+'.zip' or
            type(code['S3ObjectVersion']) is not str or not 1<=len(code['S3ObjectVersion'])<=1024 or code['S3ObjectVersion']=='null'):
        raise StateError('Recovery package must use an immutable versioned object')
    return {'AWSTemplateFormatVersion':'2010-09-09','Description':'Isolated disabled Inspector recovery function; logs-only role.',
        'Resources':{
            'RecoveryLogs':{'Type':'AWS::Logs::LogGroup','Properties':{'LogGroupName':LOG,'RetentionInDays':7}},
            'RecoveryRole':{'Type':'AWS::IAM::Role','Properties':{'RoleName':ROLE,
                'AssumeRolePolicyDocument':{'Version':'2012-10-17','Statement':[{'Effect':'Allow','Principal':{'Service':'lambda.amazonaws.com'},'Action':'sts:AssumeRole'}]},
                'Policies':[{'PolicyName':'recovery001-logs-only','PolicyDocument':{'Version':'2012-10-17','Statement':[{
                    'Effect':'Allow','Action':['logs:CreateLogStream','logs:PutLogEvents'],
                    'Resource':'arn:aws:logs:ca-central-1:666730517561:log-group:'+LOG+':*'}]}}]}},
            'RecoveryFunction':{'Type':'AWS::Lambda::Function','DependsOn':'RecoveryLogs','Properties':{
                'FunctionName':FUNCTION,'Runtime':'python3.12','Architectures':['x86_64'],'Handler':HANDLER,
                'Role':{'Fn::GetAtt':['RecoveryRole','Arn']},'Code':dict(code),'Timeout':180,'MemorySize':256,
                'ReservedConcurrentExecutions':0,'Environment':{'Variables':{'FACTORY_INSPECTOR_RECOVERY001_ENABLED':'false'}}}}}}


def validate_changes(template,changes,package,code):
    expected=render(package,code)
    prefix='arn:aws:cloudformation:ca-central-1:666730517561:stack/'+STACK+'/'
    if (template!=expected or changes.get('Status')!='CREATE_COMPLETE' or changes.get('ExecutionStatus')!='AVAILABLE' or
            changes.get('NextToken') or changes.get('Parameters') or not str(changes.get('StackId','')).startswith(prefix)):
        raise StateError('Recovery disabled preview differs or is incomplete')
    rows=changes.get('Changes',[])
    names=[row.get('ResourceChange',{}).get('LogicalResourceId') for row in rows]
    if len(names)!=3 or set(names)!=set(expected['Resources']):raise StateError('Unexpected recovery resources')
    for row in rows:
        resource=row['ResourceChange']
        if (row.get('Type')!='Resource' or resource.get('Action')!='Add' or
                resource.get('ResourceType')!=expected['Resources'][resource['LogicalResourceId']]['Type']):
            raise StateError('Recovery staging may only add its three isolated resources')
    return {'status':'VALIDATED_NOT_EXECUTED','model_calls':0,'provider_permissions':0,'ledger_permissions':0,'execution_enabled':False}
