"""Prepare the exact Builder acceptance IAM change set without executing it.

The Lambda operational switch remains false; preparation authorizes no calls.
"""
from __future__ import annotations

import hashlib
import json
import sys
import uuid
from pathlib import Path

try:
    from .prepare_role_deployment import ACCOUNT, REGION, ROOT, aws, source
except ImportError:
    from prepare_role_deployment import ACCOUNT, REGION, ROOT, aws, source

STACK = 'tims-factory-roles'
TEMPLATE = ROOT / 'infra/roles/functions.cloudformation.json'


def validate_changes(changes):
    resources = {change['ResourceChange'].get('LogicalResourceId'): change['ResourceChange']
                 for change in changes}
    if len(changes) != 2 or set(resources) != {'BuilderRole', 'BuilderFunction'}:
        raise RuntimeError('acceptance IAM must affect only BuilderRole and its Lambda role reference')
    role, function = resources['BuilderRole'], resources['BuilderFunction']
    if (role.get('ResourceType') != 'AWS::IAM::Role' or
            role.get('Action') != 'Modify' or role.get('Replacement') != 'False' or
            function.get('ResourceType') != 'AWS::Lambda::Function' or
            function.get('Action') != 'Modify' or function.get('Replacement') != 'False' or
            function.get('Scope') != ['Properties'] or
            len(function.get('Details', [])) != 1):
        raise RuntimeError('acceptance IAM change set has unexpected resource changes')
    detail = function['Details'][0]
    if (detail.get('Target') != {'Attribute': 'Properties', 'Name': 'Role',
                                 'RequiresRecreation': 'Never'} or
            detail.get('Evaluation') != 'Dynamic' or
            detail.get('ChangeSource') != 'ResourceAttribute' or
            detail.get('CausingEntity') != 'BuilderRole.Arn'):
        raise RuntimeError('BuilderFunction must change only through BuilderRole.Arn')


def validate_deployed_template(deployed):
    if isinstance(deployed, str):
        deployed = json.loads(deployed)
    proposed = json.loads(TEMPLATE.read_text(encoding='utf-8'))
    for name, resource in proposed['Resources'].items():
        if name != 'BuilderRole' and deployed['Resources'].get(name) != resource:
            raise RuntimeError(f'deployed {name} differs from the proposed template')
    if set(deployed['Resources']) != set(proposed['Resources']):
        raise RuntimeError('deployed resource set differs from the proposed template')


def validate_template():
    template = json.loads(TEMPLATE.read_text(encoding='utf-8'))
    parameters = template['Parameters']['EnableBuilderAcceptanceIam']
    if parameters.get('Default') != 'false' or parameters.get('AllowedValues') != ['false', 'true']:
        raise RuntimeError('Builder IAM parameter must default off')
    functions = [template['Resources'][role + 'Function'] for role in ('Planner', 'Builder', 'Inspector')]
    if any(f['Properties']['Environment']['Variables'].get(
            'FACTORY_OPERATIONAL_EXECUTION_ENABLED') != 'false' for f in functions):
        raise RuntimeError('role operational execution must remain disabled')
    policy = template['Resources']['BuilderRole']['Properties']['Policies'][1]['Fn::If']
    if policy[0] != 'BuilderAcceptanceIamEnabled' or policy[2] != {'Ref': 'AWS::NoValue'}:
        raise RuntimeError('acceptance IAM must be conditional')
    return hashlib.sha256(TEMPLATE.read_bytes()).hexdigest()


def prepare(plan_path):
    commit = source()
    if aws('sts', 'get-caller-identity').get('Account') != ACCOUNT:
        raise RuntimeError('wrong AWS account')
    stack = aws('cloudformation', 'describe-stacks', '--stack-name', STACK)['Stacks'][0]
    if stack['StackStatus'] not in {'CREATE_COMPLETE', 'UPDATE_COMPLETE'}:
        raise RuntimeError('role stack has no completed deployment')
    current = {p['ParameterKey']: p['ParameterValue'] for p in stack['Parameters']}
    if current.get('EnableBuilderAcceptanceIam', 'false') != 'false':
        raise RuntimeError('Builder acceptance IAM is already enabled')
    template_sha = validate_template()
    validate_deployed_template(aws('cloudformation', 'get-template', '--stack-name', STACK)['TemplateBody'])
    aws('cloudformation', 'validate-template', '--template-body', 'file://' + str(TEMPLATE))
    parameters = [{'ParameterKey': key, 'UsePreviousValue': True} for key in
                  ('ArtifactBucket', 'ArtifactKey', 'ArtifactVersion', 'CodeSha256')]
    parameters.append({'ParameterKey': 'EnableBuilderAcceptanceIam', 'ParameterValue': 'true'})
    name = 'builder-acceptance-iam-' + commit[:12] + '-' + uuid.uuid4().hex[:8]
    created = aws('cloudformation', 'create-change-set', '--stack-name', STACK,
                  '--change-set-name', name, '--change-set-type', 'UPDATE',
                  '--template-body', 'file://' + str(TEMPLATE), '--parameters', json.dumps(parameters),
                  '--capabilities', 'CAPABILITY_NAMED_IAM')
    arn = created['Id']
    aws('cloudformation', 'wait', 'change-set-create-complete', '--change-set-name', arn)
    change_set = aws('cloudformation', 'describe-change-set', '--change-set-name', arn)
    validate_changes(change_set['Changes'])
    plan = {'status': 'PREPARED_NOT_EXECUTED', 'source_commit': commit,
            'stack_id': stack['StackId'], 'change_set_arn': arn,
            'template_sha256': template_sha, 'changes': change_set['Changes'],
            'operational_execution_enabled': False, 'model_calls_authorized': 0}
    Path(plan_path).write_text(json.dumps(plan, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({'status': plan['status'], 'source_commit': commit,
                      'change_set_arn': arn, 'resources': ['BuilderRole', 'BuilderFunction'],
                      'action': 'Modify', 'replacement': False,
                      'operational_execution_enabled': False,
                      'model_calls_authorized': 0}))


def load_plan(plan_path, expected_status):
    plan = json.loads(Path(plan_path).read_text(encoding='utf-8'))
    if (plan.get('status') != expected_status or
            plan.get('source_commit') != source() or
            plan.get('template_sha256') != validate_template() or
            plan.get('operational_execution_enabled') is not False or
            plan.get('model_calls_authorized') != 0 or
            aws('sts', 'get-caller-identity').get('Account') != ACCOUNT):
        raise RuntimeError('Builder IAM plan differs from the reviewed source or account')
    validate_changes(plan['changes'])
    return plan


def current_stack(plan, *, before_update=False):
    stack = aws('cloudformation', 'describe-stacks', '--stack-name', STACK)['Stacks'][0]
    allowed = {'CREATE_COMPLETE', 'UPDATE_COMPLETE'} if before_update else {'UPDATE_COMPLETE'}
    if stack['StackId'] != plan['stack_id'] or stack['StackStatus'] not in allowed:
        raise RuntimeError('Builder role stack identity or status changed')
    return stack


def validate_change_set(plan, expected_status):
    change_set = aws('cloudformation', 'describe-change-set',
                     '--change-set-name', plan['change_set_arn'])
    if (change_set.get('StackId') != plan['stack_id'] or
            change_set.get('ExecutionStatus') != expected_status or
            change_set.get('Status') != 'CREATE_COMPLETE' or
            change_set.get('Changes') != plan['changes']):
        raise RuntimeError('reviewed Builder IAM change set changed or is unavailable')
    validate_changes(change_set['Changes'])
    return change_set


def execute(plan_path):
    plan = load_plan(plan_path, 'PREPARED_NOT_EXECUTED')
    stack = current_stack(plan, before_update=True)
    current = {p['ParameterKey']: p['ParameterValue'] for p in stack['Parameters']}
    if current.get('EnableBuilderAcceptanceIam', 'false') != 'false':
        raise RuntimeError('Builder IAM parameter already changed')
    validate_deployed_template(aws('cloudformation', 'get-template',
                                   '--stack-name', STACK)['TemplateBody'])
    change_set = validate_change_set(plan, 'AVAILABLE')
    parameters = {p['ParameterKey']: p['ParameterValue'] for p in change_set['Parameters']}
    if (parameters.get('EnableBuilderAcceptanceIam') != 'true' or
            any(parameters.get(key) != current.get(key) for key in
                ('ArtifactBucket', 'ArtifactKey', 'ArtifactVersion', 'CodeSha256'))):
        raise RuntimeError('Builder IAM change set parameters differ from running stack')
    aws('cloudformation', 'execute-change-set', '--change-set-name', plan['change_set_arn'])
    aws('cloudformation', 'wait', 'stack-update-complete', '--stack-name', STACK)
    plan['status'] = 'DEPLOYED_PENDING_VERIFICATION'
    Path(plan_path).write_text(json.dumps(plan, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({'status': plan['status'], 'source_commit': plan['source_commit']}))


def reconcile(plan_path):
    plan = load_plan(plan_path, 'PREPARED_NOT_EXECUTED')
    validate_change_set(plan, 'EXECUTE_COMPLETE')
    stack = current_stack(plan)
    if {p['ParameterKey']: p['ParameterValue'] for p in stack['Parameters']}.get(
            'EnableBuilderAcceptanceIam') != 'true':
        raise RuntimeError('Builder IAM was not enabled by reviewed change set')
    plan['status'] = 'DEPLOYED_PENDING_VERIFICATION'
    Path(plan_path).write_text(json.dumps(plan, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({'status': plan['status'], 'reconciled': True}))


def verify(plan_path):
    plan = load_plan(plan_path, 'DEPLOYED_PENDING_VERIFICATION')
    stack = current_stack(plan)
    parameters = {p['ParameterKey']: p['ParameterValue'] for p in stack['Parameters']}
    if parameters.get('EnableBuilderAcceptanceIam') != 'true':
        raise RuntimeError('Builder IAM parameter is not enabled')
    validate_change_set(plan, 'EXECUTE_COMPLETE')
    role = 'tims-factory-executor-builder'
    budget_policy = f'arn:aws:iam::{ACCOUNT}:policy/tims-software-factory-acceptance-budget-builder'
    attached = aws('iam', 'list-attached-role-policies', '--role-name', role)
    if (attached.get('IsTruncated') or
            {p['PolicyArn'] for p in attached['AttachedPolicies']} != {budget_policy}):
        raise RuntimeError('Builder managed policy attachments differ from exact budget')
    inline = aws('iam', 'get-role-policy', '--role-name', role,
                 '--policy-name', 'bounded-acceptance-builder')['PolicyDocument']
    if isinstance(inline, str):
        from urllib.parse import unquote
        inline = json.loads(unquote(inline))
    expected = json.loads(TEMPLATE.read_text(encoding='utf-8'))['Resources'][
        'BuilderRole']['Properties']['Policies'][1]['Fn::If'][1]['PolicyDocument']
    for statement in expected['Statement']:
        if statement['Sid'] == 'OwnExactAcceptanceExecution':
            statement['Resource'] = (f'arn:aws:dynamodb:{REGION}:{ACCOUNT}:'
                                     'table/tims-factory-role-executions')
    if inline != expected:
        raise RuntimeError('Builder acceptance inline policy differs from reviewed template')
    config = aws('lambda', 'get-function-configuration', '--function-name', 'tims-factory-builder')
    if (config.get('Role') != f'arn:aws:iam::{ACCOUNT}:role/{role}' or
            config.get('CodeSha256') != parameters.get('CodeSha256') or
            config.get('State') != 'Active' or
            config.get('LastUpdateStatus') != 'Successful' or
            config.get('Environment', {}).get('Variables', {}).get(
                'FACTORY_OPERATIONAL_EXECUTION_ENABLED') != 'false'):
        raise RuntimeError('Builder code, role, or disabled operational boundary differs')
    plan['status'] = 'IAM_ENABLED_OPERATIONAL_DISABLED_VERIFIED'
    Path(plan_path).write_text(json.dumps(plan, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({'status': plan['status'], 'source_commit': plan['source_commit'],
                      'budget_policy_attached': True, 'inline_policy_verified': True,
                      'operational_execution_enabled': False, 'model_calls_by_verifier': 0}))


if __name__ == '__main__':
    if len(sys.argv) == 2:
        prepare(sys.argv[1])
    elif len(sys.argv) == 3 and sys.argv[1] in {'prepare', 'execute', 'reconcile', 'verify'}:
        globals()[sys.argv[1]](sys.argv[2])
    else:
        raise SystemExit('usage: prepare_builder_acceptance_iam.py [prepare|execute|reconcile|verify] PLAN_JSON')
