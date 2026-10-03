"""Offline isolated attempt table and exact-role access; never deploys or calls models."""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))
from factory_runtime.pilot002_attempts import TABLE, ROLES, key
from factory_state.model import StateError

STACK = 'tims-factory-pilot-002-attempts'
IAM_ROLES = {'builder': 'tims-factory-acceptance-broker-canary',
             'inspector': 'tims-factory-executor-inspector', 'qa': 'tims-factory-google-qa-broker'}


def render():
    resources = {'Attempts': {'Type': 'AWS::DynamoDB::Table', 'DeletionPolicy': 'Retain',
        'UpdateReplacePolicy': 'Retain', 'Properties': {'TableName': TABLE,
            'BillingMode': 'PAY_PER_REQUEST', 'DeletionProtectionEnabled': True,
            'AttributeDefinitions': [{'AttributeName': 'PK', 'AttributeType': 'S'}],
            'KeySchema': [{'AttributeName': 'PK', 'KeyType': 'HASH'}],
            'SSESpecification': {'SSEEnabled': True}}}}
    for role in ROLES:
        resources[role.title()+'AttemptPolicy'] = {'Type': 'AWS::IAM::Policy', 'Properties': {
            'PolicyName': 'pilot-002-'+role+'-attempt-only', 'Roles': [IAM_ROLES[role]],
            'PolicyDocument': {'Version': '2012-10-17', 'Statement': [{
                'Effect': 'Allow', 'Action': ['dynamodb:GetItem', 'dynamodb:PutItem', 'dynamodb:UpdateItem'],
                'Resource': {'Fn::GetAtt': ['Attempts', 'Arn']}, 'Condition': {
                    'ForAllValues:StringEquals': {'dynamodb:LeadingKeys': [key(role)['PK']['S']]},
                    'Null': {'dynamodb:LeadingKeys': 'false'}}}]}}}
    return {'AWSTemplateFormatVersion': '2010-09-09',
        'Description': 'Pilot 002 isolated attempt ledger. No model or execution activation.',
        'Resources': resources}


def validate_changes(template, change_set):
    expected = render()
    prefix = 'arn:aws:cloudformation:ca-central-1:666730517561:stack/'+STACK+'/'
    if (template != expected or change_set.get('Status') != 'CREATE_COMPLETE' or
            change_set.get('ExecutionStatus') != 'AVAILABLE' or change_set.get('NextToken') or
            change_set.get('Parameters') or not str(change_set.get('StackId', '')).startswith(prefix)):
        raise StateError('Pilot 002 attempt proposal changed or is incomplete')
    changes = change_set.get('Changes', [])
    names = [x.get('ResourceChange', {}).get('LogicalResourceId') for x in changes]
    if len(names) != 4 or set(names) != set(expected['Resources']):
        raise StateError('Pilot 002 attempt proposal has unexpected resources')
    for x in changes:
        r = x['ResourceChange']
        if (x.get('Type') != 'Resource' or r.get('Action') != 'Add' or
                r.get('ResourceType') != expected['Resources'][r['LogicalResourceId']]['Type']):
            raise StateError('Pilot 002 attempt proposal must only add four resources')
    return {'status': 'VALIDATED_NOT_EXECUTED', 'model_calls': 0}


if __name__ == '__main__':
    with Path(sys.argv[1]).open('x', encoding='utf-8') as stream:
        stream.write(json.dumps(render(), indent=2)+'\n')
    print('PREPARED_NOT_AUTHORIZED: one table and three exact-row policies')
