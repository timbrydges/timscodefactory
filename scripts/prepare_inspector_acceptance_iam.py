"""Prepare and verify the exact Inspector Sonnet 4.5 fallback IAM change set.

Preparation creates only a CloudFormation change set. Execution is a separate,
explicit step. The Inspector Lambda operational switch remains false throughout,
so enabling this IAM alone cannot invoke a model.
"""
from __future__ import annotations

import hashlib
import json
import sys
import uuid
from pathlib import Path

try:
    from .prepare_role_deployment import ACCOUNT, REGION, ROOT, aws, source
    from .verify_inspector_activation_binding import expected_reservation, verify_implementation_policy
except ImportError:
    from prepare_role_deployment import ACCOUNT, REGION, ROOT, aws, source
    from verify_inspector_activation_binding import expected_reservation, verify_implementation_policy

STACK = 'tims-factory-roles'
TEMPLATE = ROOT / 'infra/roles/functions.cloudformation.json'
PARAMETER = 'EnableInspectorAcceptanceIam'
ROLE_LOGICAL = 'InspectorRole'
FUNCTION_LOGICAL = 'InspectorFunction'
ROLE_NAME = 'tims-factory-executor-inspector'
POLICY_NAME = 'acceptance-inspector-fallback-sonnet-4-5'


def validate_changes(changes):
    resources = {change['ResourceChange'].get('LogicalResourceId'): change['ResourceChange']
                 for change in changes}
    if len(changes) != 2 or set(resources) != {ROLE_LOGICAL, FUNCTION_LOGICAL}:
        raise RuntimeError('Inspector acceptance IAM must affect only InspectorRole and InspectorFunction')
    role, function = resources[ROLE_LOGICAL], resources[FUNCTION_LOGICAL]
    if (role.get('ResourceType') != 'AWS::IAM::Role' or
            role.get('Action') != 'Modify' or role.get('Replacement') != 'False' or
            function.get('ResourceType') != 'AWS::Lambda::Function' or
            function.get('Action') != 'Modify' or function.get('Replacement') != 'False' or
            function.get('Scope') != ['Properties'] or
            len(function.get('Details', [])) != 1):
        raise RuntimeError('Inspector acceptance IAM change set has unexpected resource changes')
    detail = function['Details'][0]
    if (detail.get('Target') != {'Attribute': 'Properties', 'Name': 'Role',
                                 'RequiresRecreation': 'Never'} or
            detail.get('Evaluation') != 'Dynamic' or
            detail.get('ChangeSource') != 'ResourceAttribute' or
            detail.get('CausingEntity') != 'InspectorRole.Arn'):
        raise RuntimeError('InspectorFunction must change only through InspectorRole.Arn')


def validate_deployed_template(deployed):
    if isinstance(deployed, str):
        deployed = json.loads(deployed)
    proposed = json.loads(TEMPLATE.read_text(encoding='utf-8'))
    for name, resource in proposed['Resources'].items():
        if name != ROLE_LOGICAL and deployed['Resources'].get(name) != resource:
            raise RuntimeError(f'deployed {name} differs from the proposed template')
    if set(deployed['Resources']) != set(proposed['Resources']):
        raise RuntimeError('deployed resource set differs from the proposed template')


def validate_template():
    template = json.loads(TEMPLATE.read_text(encoding='utf-8'))
    parameters = template['Parameters'][PARAMETER]
    if parameters.get('Default') != 'false' or parameters.get('AllowedValues') != ['false', 'true']:
        raise RuntimeError('Inspector IAM parameter must default off')
    functions = [template['Resources'][role + 'Function'] for role in ('Planner', 'Builder', 'Inspector')]
    if any(f['Properties']['Environment']['Variables'].get(
            'FACTORY_OPERATIONAL_EXECUTION_ENABLED') != 'false' for f in functions):
        raise RuntimeError('role operational execution must remain disabled')
    policy = template['Resources'][ROLE_LOGICAL]['Properties']['Policies'][1]['Fn::If']
    if policy[0] != 'InspectorAcceptanceIamEnabled' or policy[2] != {'Ref': 'AWS::NoValue'}:
        raise RuntimeError('Inspector acceptance IAM must be conditional')
    document = policy[1]['PolicyDocument']
    if policy[1].get('PolicyName') != POLICY_NAME or len(document.get('Statement', [])) != 5:
        raise RuntimeError('Inspector acceptance policy differs from reviewed exact policy')
    budget = document['Statement'][3]
    if budget != expected_reservation():
        raise RuntimeError('Inspector one-call budget reservation policy differs')
    verify_implementation_policy(document)
    return hashlib.sha256(TEMPLATE.read_bytes()).hexdigest()


def prepare(plan_path):
    commit = source()
    if aws('sts', 'get-caller-identity').get('Account') != ACCOUNT:
        raise RuntimeError('wrong AWS account')
    stack = aws('cloudformation', 'describe-stacks', '--stack-name', STACK)['Stacks'][0]
    if stack['StackStatus'] not in {'CREATE_COMPLETE', 'UPDATE_COMPLETE'}:
        raise RuntimeError('role stack has no completed deployment')
    current = {p['ParameterKey']: p['ParameterValue'] for p in stack['Parameters']}
    if current.get(PARAMETER, 'false') != 'false':
        raise RuntimeError('Inspector acceptance IAM is already enabled')
    template_sha = validate_template()
    validate_deployed_template(aws('cloudformation', 'get-template', '--stack-name', STACK)['TemplateBody'])
    aws('cloudformation', 'validate-template', '--template-body', 'file://' + str(TEMPLATE))
    preserved = ('ArtifactBucket', 'ArtifactKey', 'ArtifactVersion', 'CodeSha256',
                 'EnableBuilderAcceptanceIam')
    parameters = [{'ParameterKey': key, 'UsePreviousValue': True} for key in preserved]
    parameters.append({'ParameterKey': PARAMETER, 'ParameterValue': 'true'})
    name = 'inspector-acceptance-iam-' + commit[:12] + '-' + uuid.uuid4().hex[:8]
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
            'builder_acceptance_iam_preserved': current.get('EnableBuilderAcceptanceIam', 'false'),
            'operational_execution_enabled': False, 'model_calls_authorized': 0}
    Path(plan_path).write_text(json.dumps(plan, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({'status': plan['status'], 'source_commit': commit,
                      'change_set_arn': arn,
                      'resources': [ROLE_LOGICAL, FUNCTION_LOGICAL],
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
        raise RuntimeError('Inspector IAM plan differs from the reviewed source or account')
    validate_changes(plan['changes'])
    return plan


def current_stack(plan, *, before_update=False):
    stack = aws('cloudformation', 'describe-stacks', '--stack-name', STACK)['Stacks'][0]
    allowed = {'CREATE_COMPLETE', 'UPDATE_COMPLETE'} if before_update else {'UPDATE_COMPLETE'}
    if stack['StackId'] != plan['stack_id'] or stack['StackStatus'] not in allowed:
        raise RuntimeError('Inspector role stack identity or status changed')
    return stack


def validate_change_set(plan, expected_status):
    change_set = aws('cloudformation', 'describe-change-set',
                     '--change-set-name', plan['change_set_arn'])
    if (change_set.get('StackId') != plan['stack_id'] or
            change_set.get('ExecutionStatus') != expected_status or
            change_set.get('Status') != 'CREATE_COMPLETE' or
            change_set.get('Changes') != plan['changes']):
        raise RuntimeError('reviewed Inspector IAM change set changed or is unavailable')
    validate_changes(change_set['Changes'])
    return change_set


def execute(plan_path):
    plan = load_plan(plan_path, 'PREPARED_NOT_EXECUTED')
    stack = current_stack(plan, before_update=True)
    current = {p['ParameterKey']: p['ParameterValue'] for p in stack['Parameters']}
    if current.get(PARAMETER, 'false') != 'false':
        raise RuntimeError('Inspector IAM parameter already changed')
    if current.get('EnableBuilderAcceptanceIam', 'false') != plan['builder_acceptance_iam_preserved']:
        raise RuntimeError('Builder IAM parameter changed since Inspector plan preparation')
    validate_deployed_template(aws('cloudformation', 'get-template',
                                   '--stack-name', STACK)['TemplateBody'])
    change_set = validate_change_set(plan, 'AVAILABLE')
    parameters = {p['ParameterKey']: p['ParameterValue'] for p in change_set['Parameters']}
    if (parameters.get(PARAMETER) != 'true' or
            parameters.get('EnableBuilderAcceptanceIam') != current.get('EnableBuilderAcceptanceIam') or
            any(parameters.get(key) != current.get(key) for key in
                ('ArtifactBucket', 'ArtifactKey', 'ArtifactVersion', 'CodeSha256'))):
        raise RuntimeError('Inspector IAM change set parameters differ from running stack')
    aws('cloudformation', 'execute-change-set', '--change-set-name', plan['change_set_arn'])
    aws('cloudformation', 'wait', 'stack-update-complete', '--stack-name', STACK)
    plan['status'] = 'DEPLOYED_PENDING_VERIFICATION'
    Path(plan_path).write_text(json.dumps(plan, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({'status': plan['status'], 'source_commit': plan['source_commit']}))


def reconcile(plan_path):
    plan = load_plan(plan_path, 'PREPARED_NOT_EXECUTED')
    validate_change_set(plan, 'EXECUTE_COMPLETE')
    stack = current_stack(plan)
    params = {p['ParameterKey']: p['ParameterValue'] for p in stack['Parameters']}
    if (params.get(PARAMETER) != 'true' or
            params.get('EnableBuilderAcceptanceIam') != plan['builder_acceptance_iam_preserved']):
        raise RuntimeError('Inspector IAM deployment differs from reviewed change set')
    plan['status'] = 'DEPLOYED_PENDING_VERIFICATION'
    Path(plan_path).write_text(json.dumps(plan, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({'status': plan['status'], 'reconciled': True}))


def verify(plan_path):
    plan = load_plan(plan_path, 'DEPLOYED_PENDING_VERIFICATION')
    stack = current_stack(plan)
    parameters = {p['ParameterKey']: p['ParameterValue'] for p in stack['Parameters']}
    if (parameters.get(PARAMETER) != 'true' or
            parameters.get('EnableBuilderAcceptanceIam') != plan['builder_acceptance_iam_preserved']):
        raise RuntimeError('Inspector IAM parameters differ from reviewed deployment')
    validate_change_set(plan, 'EXECUTE_COMPLETE')
    attached = aws('iam', 'list-attached-role-policies', '--role-name', ROLE_NAME)
    if attached.get('IsTruncated') or attached.get('AttachedPolicies'):
        raise RuntimeError('Inspector role has unexpected managed policy attachments')
    inline = aws('iam', 'get-role-policy', '--role-name', ROLE_NAME,
                 '--policy-name', POLICY_NAME)['PolicyDocument']
    if isinstance(inline, str):
        from urllib.parse import unquote
        inline = json.loads(unquote(inline))
    expected = json.loads(TEMPLATE.read_text(encoding='utf-8'))['Resources'][
        ROLE_LOGICAL]['Properties']['Policies'][1]['Fn::If'][1]['PolicyDocument']
    if inline != expected:
        raise RuntimeError('Inspector acceptance inline policy differs from reviewed template')
    config = aws('lambda', 'get-function-configuration', '--function-name', 'tims-factory-inspector')
    if (config.get('Role') != f'arn:aws:iam::{ACCOUNT}:role/{ROLE_NAME}' or
            config.get('CodeSha256') != parameters.get('CodeSha256') or
            config.get('State') != 'Active' or
            config.get('LastUpdateStatus') != 'Successful' or
            config.get('Environment', {}).get('Variables', {}).get(
                'FACTORY_OPERATIONAL_EXECUTION_ENABLED') != 'false'):
        raise RuntimeError('Inspector code, role, or disabled operational boundary differs')
    plan['status'] = 'IAM_ENABLED_OPERATIONAL_DISABLED_VERIFIED'
    Path(plan_path).write_text(json.dumps(plan, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({'status': plan['status'], 'source_commit': plan['source_commit'],
                      'inline_policy_verified': True,
                      'operational_execution_enabled': False,
                      'model_calls_by_verifier': 0}))


if __name__ == '__main__':
    if len(sys.argv) == 2:
        prepare(sys.argv[1])
    elif len(sys.argv) == 3 and sys.argv[1] in {'prepare', 'execute', 'reconcile', 'verify'}:
        globals()[sys.argv[1]](sys.argv[2])
    else:
        raise SystemExit('usage: prepare_inspector_acceptance_iam.py '
                         '[prepare|execute|reconcile|verify] PLAN_JSON')
