"""Exact disabled handoff foundation; no signing, model calls or execution grants."""
import copy
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'src'))
from factory_runtime.handoff001_attempts import TABLE, ROLES
from factory_runtime.handoff001_entrypoint import EXECUTION_ROLES
from factory_state.model import StateError

STACK = 'tims-factory-handoff-001-disabled'
REGION = 'ca-central-1'
ACCOUNT = '666730517561'


def render(*, source_commit, code):
    if (not isinstance(source_commit, str) or not re.fullmatch('[0-9a-f]{40}', source_commit) or
            not isinstance(code, dict) or set(code) != {'S3Bucket', 'S3Key', 'S3ObjectVersion'} or
            any(not isinstance(v, str) or not v or len(v)>1024 for v in code.values()) or code['S3ObjectVersion']=='null'):
        raise StateError('Handoff foundation requires reviewed source and immutable object version')
    resources = {'Attempts': {'Type': 'AWS::DynamoDB::Table', 'DeletionPolicy': 'Retain',
        'UpdateReplacePolicy': 'Retain', 'Properties': {'TableName': TABLE, 'BillingMode': 'PAY_PER_REQUEST',
            'DeletionProtectionEnabled': True, 'AttributeDefinitions': [{'AttributeName': 'PK', 'AttributeType': 'S'}],
            'KeySchema': [{'AttributeName': 'PK', 'KeyType': 'HASH'}], 'SSESpecification': {'SSEEnabled': True}}}}
    for role in ROLES:
        prefix = role.title(); name = 'tims-factory-handoff-001-'+role
        resources[prefix+'Logs'] = {'Type': 'AWS::Logs::LogGroup', 'DeletionPolicy': 'Retain',
            'UpdateReplacePolicy': 'Retain', 'Properties': {'LogGroupName': '/aws/lambda/'+name, 'RetentionInDays': 7}}
        resources[prefix+'Function'] = {'Type': 'AWS::Lambda::Function', 'DependsOn': prefix+'Logs', 'Properties': {
            'FunctionName': name, 'Description': 'Fresh handoff disabled foundation; no signed allowance installed',
            'Runtime': 'python3.12', 'Architectures': ['x86_64'], 'MemorySize': 256, 'Timeout': 180,
            'Handler': 'factory_runtime.handoff001_entrypoint.handler',
            'Role': 'arn:aws:iam::'+ACCOUNT+':role/'+EXECUTION_ROLES[role], 'Code': copy.deepcopy(code),
            'ReservedConcurrentExecutions': 0, 'Environment': {'Variables': {
                'FACTORY_HANDOFF001_ENABLED': 'false', 'FACTORY_HANDOFF001_ROLE': role}},
            'Tags': [{'Key': 'SourceCommit', 'Value': source_commit}, {'Key': 'Purpose', 'Value': 'disabled-handoff-foundation'}]}}
    return {'AWSTemplateFormatVersion': '2010-09-09',
        'Description': 'Disabled handoff functions and separate retained attempts table; no IAM modifications.', 'Resources': resources}


def validate_changes(template, change_set, *, source_commit, code):
    expected = render(source_commit=source_commit, code=code)
    if (template != expected or change_set.get('Status') != 'CREATE_COMPLETE' or
            change_set.get('ExecutionStatus') != 'AVAILABLE' or change_set.get('NextToken') or
            change_set.get('Parameters') or not str(change_set.get('StackId', '')).startswith(
                f'arn:aws:cloudformation:{REGION}:{ACCOUNT}:stack/{STACK}/')):
        raise StateError('Handoff foundation preview differs or is incomplete')
    changes = change_set.get('Changes', [])
    names = [item.get('ResourceChange', {}).get('LogicalResourceId') for item in changes]
    if len(names) != len(expected['Resources']) or set(names) != set(expected['Resources']):
        raise StateError('Handoff foundation must add exactly seven resources')
    for item in changes:
        value = item['ResourceChange']
        if (item.get('Type') != 'Resource' or value.get('Action') != 'Add' or
                value.get('ResourceType') != expected['Resources'][value['LogicalResourceId']]['Type']):
            raise StateError('Handoff foundation must not modify or remove existing resources')
    return {'status': 'VALIDATED_NOT_EXECUTED', 'model_calls': 0, 'iam_changes': 0,
        'new_functions': 3, 'new_log_groups': 3, 'new_attempt_table': 1, 'reserved_concurrency': 0}
