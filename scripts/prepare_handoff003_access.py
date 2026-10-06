"""Add exact handoff permissions without changing the disabled foundation."""
import copy
from prepare_handoff003_foundation import render as foundation, STACK, ACCOUNT, REGION
from prepare_pilot002_access import policy as previous_policy
from factory_runtime.handoff003_attempts import TABLE, ROLES, key
from factory_runtime.handoff003_entrypoint import EXECUTION_ROLES
from factory_state.model import StateError


def policy(role):
    if role not in ROLES:
        raise StateError('Unknown handoff role')
    # Reuse the reviewed fixed provider routes, never the old attempt row.
    document = previous_policy(role)
    row = document['Statement'][0]
    row['Resource'] = f'arn:aws:dynamodb:{REGION}:{ACCOUNT}:table/{TABLE}'
    row['Condition']['ForAllValues:StringEquals']['dynamodb:LeadingKeys'] = [key(role)['PK']['S']]
    name = 'tims-factory-handoff-003-'+role
    document['Statement'].append({'Sid': 'OwnHandoffLogs', 'Effect': 'Allow',
        'Action': ['logs:CreateLogStream', 'logs:PutLogEvents'],
        'Resource': f'arn:aws:logs:{REGION}:{ACCOUNT}:log-group:/aws/lambda/{name}:*'})
    for statement in document['Statement']:
        # KMS decrypt is performed by Secrets Manager and is already constrained
        # to the exact secret/version and ViaService. It has no Lambda source key.
        if statement['Action'] != 'kms:Decrypt':
            statement.setdefault('Condition', {}).setdefault('ArnEquals', {})['lambda:SourceFunctionArn'] = (
                f'arn:aws:lambda:{REGION}:{ACCOUNT}:function:{name}')
    return document


def render(current, *, source_commit, code):
    if current != foundation(source_commit=source_commit, code=code):
        raise StateError('Disabled foundation differs; reconcile before permissions')
    result = copy.deepcopy(current)
    for role in ROLES:
        result['Resources'][role.title()+'Access'] = {'Type': 'AWS::IAM::Policy', 'Properties': {
            'PolicyName': 'handoff003-own-attempt-and-provider',
            'Roles': [EXECUTION_ROLES[role]], 'PolicyDocument': policy(role)}}
    return result


def validate_changes(template, change_set, *, current, source_commit, code):
    if (template != render(current, source_commit=source_commit, code=code) or
            change_set.get('Status') != 'CREATE_COMPLETE' or change_set.get('ExecutionStatus') != 'AVAILABLE' or
            change_set.get('NextToken') or change_set.get('Parameters') or
            not str(change_set.get('StackId', '')).startswith(
                f'arn:aws:cloudformation:{REGION}:{ACCOUNT}:stack/{STACK}/')):
        raise StateError('Handoff access preview differs or is incomplete')
    changes = change_set.get('Changes', [])
    names = [item.get('ResourceChange', {}).get('LogicalResourceId') for item in changes]
    if len(names) != 3 or set(names) != {role.title()+'Access' for role in ROLES}:
        raise StateError('Handoff access must add exactly three policies')
    for item in changes:
        change = item['ResourceChange']
        if item.get('Type') != 'Resource' or change.get('Action') != 'Add' or change.get('ResourceType') != 'AWS::IAM::Policy':
            raise StateError('Handoff access cannot modify existing resources')
    return {'status': 'ACCESS_VALIDATED_NOT_EXECUTED', 'new_policies': 3,
        'execution_enabled': False, 'reserved_concurrency': 0, 'model_calls': 0}
