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
    if (len(changes) != 1 or
            changes[0]['ResourceChange'].get('LogicalResourceId') != 'BuilderRole' or
            changes[0]['ResourceChange'].get('ResourceType') != 'AWS::IAM::Role' or
            changes[0]['ResourceChange'].get('Action') != 'Modify' or
            changes[0]['ResourceChange'].get('Replacement') != 'False'):
        raise RuntimeError('acceptance IAM must modify only BuilderRole in place')


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
                      'change_set_arn': arn, 'resource': 'BuilderRole',
                      'action': 'Modify', 'replacement': False,
                      'operational_execution_enabled': False,
                      'model_calls_authorized': 0}))


if __name__ == '__main__':
    if len(sys.argv) != 2:
        raise SystemExit('usage: prepare_builder_acceptance_iam.py PLAN_JSON')
    prepare(sys.argv[1])
