"""Prepare only the permanent controller ledger; no execution permissions."""
from factory_runtime.handoff002_dispatch import TABLE
from factory_state.model import StateError

STACK = 'tims-factory-handoff-002-controller-ledger'


def render():
    return {'AWSTemplateFormatVersion': '2010-09-09', 'Resources': {
        'DispatchLedger': {'Type': 'AWS::DynamoDB::Table',
            'DeletionPolicy': 'Retain', 'UpdateReplacePolicy': 'Retain',
            'Properties': {'TableName': TABLE, 'BillingMode': 'PAY_PER_REQUEST',
                'DeletionProtectionEnabled': True,
                'AttributeDefinitions': [{'AttributeName': 'PK', 'AttributeType': 'S'}],
                'KeySchema': [{'AttributeName': 'PK', 'KeyType': 'HASH'}],
                'SSESpecification': {'SSEEnabled': True}}}}}


def validate_changes(template, change_set):
    if (template != render() or change_set.get('Status') != 'CREATE_COMPLETE' or
            change_set.get('ExecutionStatus') != 'AVAILABLE' or change_set.get('NextToken') or
            change_set.get('Parameters') or not str(change_set.get('StackId', '')).startswith(
                'arn:aws:cloudformation:ca-central-1:666730517561:stack/'+STACK+'/')):
        raise StateError('Controller ledger preview differs or is incomplete')
    changes = change_set.get('Changes', [])
    if len(changes) != 1:
        raise StateError('Exactly one new ledger required')
    value = changes[0].get('ResourceChange', {})
    if (changes[0].get('Type') != 'Resource' or value.get('LogicalResourceId') != 'DispatchLedger' or
            value.get('ResourceType') != 'AWS::DynamoDB::Table' or value.get('Action') != 'Add'):
        raise StateError('Existing resources must not change')
    return {'status': 'VALIDATED_NOT_EXECUTED', 'new_tables': 1,
        'execution_permissions': 0, 'model_calls': 0}
