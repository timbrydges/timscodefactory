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
    from .prepare_role_deployment import ACCOUNT, ROOT, aws, source
except ImportError:
    from prepare_role_deployment import ACCOUNT, ROOT, aws, source

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


if __name__ == '__main__':
    if len(sys.argv) != 2:
        raise SystemExit('usage: prepare_builder_acceptance_iam.py PLAN_JSON')
    prepare(sys.argv[1])
