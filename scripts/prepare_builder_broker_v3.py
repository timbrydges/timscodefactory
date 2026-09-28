"""Retarget disabled Builder IAM from broker :2 to verified broker :3.

The change set must update only BuilderRole and CloudFormation's dynamic
BuilderFunction role reference. No code, Lambda version, or enable flag changes.
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
ROLE = 'tims-factory-executor-builder'
BROKER = f'arn:aws:lambda:{REGION}:{ACCOUNT}:function:tims-factory-provider-broker:3'
OLD_BROKER = BROKER[:-1] + '2'
POLICY_NAME = 'bounded-acceptance-builder'


def _template():
    template = json.loads(TEMPLATE.read_text(encoding='utf-8'))
    role = template['Resources']['BuilderRole']['Properties']
    if (template['Parameters']['EnableBuilderAcceptanceIam'].get('Default') != 'false' or
            role['Policies'][1]['Fn::If'][0] != 'BuilderAcceptanceIamEnabled' or
            role['Policies'][1]['Fn::If'][2] != {'Ref': 'AWS::NoValue'}):
        raise RuntimeError('Builder IAM must remain conditional and default disabled')
    statements = role['Policies'][1]['Fn::If'][1]['PolicyDocument']['Statement']
    matches = [statement for statement in statements if
               statement.get('Sid') == 'InvokePinnedCredentialFreeBroker']
    if (len(matches) != 1 or matches[0] != {
            'Sid': 'InvokePinnedCredentialFreeBroker', 'Effect': 'Allow',
            'Action': ['lambda:InvokeFunction'], 'Resource': BROKER}):
        raise RuntimeError('Builder broker invocation must pin version 3 exactly')
    for name in ('Planner', 'Builder', 'Inspector'):
        env = template['Resources'][name + 'Function']['Properties']['Environment']['Variables']
        if env.get('FACTORY_OPERATIONAL_EXECUTION_ENABLED') != 'false':
            raise RuntimeError('all operational roles must remain disabled')
    return template


def validate_changes(changes):
    resources = {item['ResourceChange'].get('LogicalResourceId'): item['ResourceChange']
                 for item in changes}
    if len(changes) != 2 or set(resources) != {'BuilderRole', 'BuilderFunction'}:
        raise RuntimeError('broker pin update must touch only BuilderRole and BuilderFunction')
    for name, property_name, source_name, evaluation, cause in (
            ('BuilderRole', 'Policies', 'DirectModification', 'Static', None),
            ('BuilderFunction', 'Role', 'ResourceAttribute', 'Dynamic', 'BuilderRole.Arn')):
        item = resources[name]
        details = item.get('Details')
        if (item.get('Action') != 'Modify' or item.get('Replacement') != 'False' or
                item.get('Scope') != ['Properties'] or
                not isinstance(details, list) or not details):
            raise RuntimeError('Builder broker pin change must be in place and property-only')
        for detail in details:
            target = detail.get('Target', {})
            if (target.get('Attribute') != 'Properties' or
                    target.get('Name') != property_name or
                    target.get('RequiresRecreation') != 'Never' or
                    detail.get('ChangeSource') != source_name or
                    detail.get('Evaluation') != evaluation or
                    detail.get('CausingEntity') != cause):
                raise RuntimeError('Builder broker pin change has unexpected dependency')


def _stack():
    stack = aws('cloudformation', 'describe-stacks', '--stack-name', STACK)['Stacks'][0]
    if stack.get('StackStatus') not in {'CREATE_COMPLETE', 'UPDATE_COMPLETE'}:
        raise RuntimeError('Builder stack is not ready')
    params = {p['ParameterKey']: p['ParameterValue'] for p in stack['Parameters']}
    if params.get('EnableBuilderAcceptanceIam') != 'true':
        raise RuntimeError('reviewed Builder acceptance IAM is not enabled')
    return stack, params


def _old_template_matches(proposed):
    deployed = aws('cloudformation', 'get-template', '--stack-name', STACK)['TemplateBody']
    if isinstance(deployed, str):
        deployed = json.loads(deployed)
    expected = json.loads(json.dumps(proposed))
    statements = expected['Resources']['BuilderRole']['Properties']['Policies'][1][
        'Fn::If'][1]['PolicyDocument']['Statement']
    for statement in statements:
        if statement.get('Sid') == 'InvokePinnedCredentialFreeBroker':
            statement['Resource'] = OLD_BROKER
    if deployed != expected:
        raise RuntimeError('deployed Builder template differs beyond broker version 2')


def _version(stack):
    outputs = {p['OutputKey']: p['OutputValue'] for p in stack['Outputs']}
    version = outputs.get('BuilderVersionArn')
    if not isinstance(version, str) or not version.startswith(
            f'arn:aws:lambda:{REGION}:{ACCOUNT}:function:tims-factory-builder:'):
        raise RuntimeError('Builder version output differs')
    return version


def _disabled(arn, expected_code):
    config = aws('lambda', 'get-function-configuration', '--function-name', arn)
    if (config.get('FunctionArn') != arn or
            config.get('Role') != f'arn:aws:iam::{ACCOUNT}:role/{ROLE}' or
            config.get('CodeSha256') != expected_code or
            config.get('Environment', {}).get('Variables') != {
                'FACTORY_ROLE': 'builder',
                'FACTORY_OPERATIONAL_EXECUTION_ENABLED': 'false',
                'EXECUTION_TABLE': 'tims-factory-role-executions'} or
            config.get('State') != 'Active'):
        raise RuntimeError('Builder function is not the expected disabled code')


def _broker_disabled():
    config = aws('lambda', 'get-function-configuration', '--function-name', BROKER)
    if (config.get('FunctionArn') != BROKER or
            config.get('Environment', {}).get('Variables') != {
                'FACTORY_ACCEPTANCE_BROKER_ENABLED': 'false',
                'FACTORY_ACCEPTANCE_ACTIVATION_JSON': '',
                'FACTORY_OPENAI_SECRET_ARN': ''} or
            config.get('State') != 'Active'):
        raise RuntimeError('broker version 3 is not disabled')


def _plan(path, status):
    plan = json.loads(Path(path).read_text(encoding='utf-8'))
    _template()
    if (plan.get('status') != status or plan.get('source_commit') != source() or
            plan.get('template_sha256') != hashlib.sha256(TEMPLATE.read_bytes()).hexdigest() or
            plan.get('model_calls_authorized') != 0 or
            aws('sts', 'get-caller-identity').get('Account') != ACCOUNT):
        raise RuntimeError('Builder broker pin plan differs from reviewed source')
    validate_changes(plan['changes'])
    return plan


def prepare(path):
    commit = source()
    proposed = _template()
    if aws('sts', 'get-caller-identity').get('Account') != ACCOUNT:
        raise RuntimeError('wrong AWS account')
    stack, params = _stack()
    _old_template_matches(proposed)
    old_version = _version(stack)
    _disabled(old_version, params['CodeSha256'])
    _disabled(old_version.rsplit(':', 1)[0], params['CodeSha256'])
    _broker_disabled()
    aws('cloudformation', 'validate-template', '--template-body', 'file://' + str(TEMPLATE))
    parameters = [{'ParameterKey': key, 'UsePreviousValue': True} for key in
                  ('ArtifactBucket', 'ArtifactKey', 'ArtifactVersion', 'CodeSha256',
                   'EnableBuilderAcceptanceIam')]
    name = 'builder-broker-v3-' + commit[:12] + '-' + uuid.uuid4().hex[:8]
    created = aws('cloudformation', 'create-change-set', '--stack-name', STACK,
                  '--change-set-name', name, '--change-set-type', 'UPDATE',
                  '--template-body', 'file://' + str(TEMPLATE), '--parameters',
                  json.dumps(parameters), '--capabilities', 'CAPABILITY_NAMED_IAM')
    arn = created['Id']
    aws('cloudformation', 'wait', 'change-set-create-complete', '--change-set-name', arn)
    described = aws('cloudformation', 'describe-change-set', '--change-set-name', arn)
    validate_changes(described['Changes'])
    plan = {'status': 'PREPARED_NOT_EXECUTED', 'source_commit': commit,
            'stack_id': stack['StackId'], 'change_set_arn': arn,
            'template_sha256': hashlib.sha256(TEMPLATE.read_bytes()).hexdigest(),
            'changes': described['Changes'], 'builder_version': old_version,
            'code_sha256': params['CodeSha256'], 'model_calls_authorized': 0}
    Path(path).write_text(json.dumps(plan, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({'status': plan['status'], 'source_commit': commit,
                      'resources': ['BuilderRole', 'BuilderFunction'],
                      'builder_version': old_version, 'broker_target': BROKER}))


def execute(path):
    plan = _plan(path, 'PREPARED_NOT_EXECUTED')
    stack, params = _stack()
    if (stack['StackId'] != plan['stack_id'] or _version(stack) != plan['builder_version'] or
            params.get('CodeSha256') != plan['code_sha256']):
        raise RuntimeError('Builder deployment changed since preparation')
    _old_template_matches(_template())
    described = aws('cloudformation', 'describe-change-set',
                    '--change-set-name', plan['change_set_arn'])
    validate_changes(described['Changes'])
    if (described.get('ExecutionStatus') != 'AVAILABLE' or
            described.get('StackId') != plan['stack_id'] or
            described.get('Changes') != plan['changes']):
        raise RuntimeError('reviewed Builder broker pin change set differs')
    _disabled(plan['builder_version'], plan['code_sha256'])
    _broker_disabled()
    aws('cloudformation', 'execute-change-set', '--change-set-name', plan['change_set_arn'])
    aws('cloudformation', 'wait', 'stack-update-complete', '--stack-name', STACK)
    plan['status'] = 'DEPLOYED_PENDING_VERIFICATION'
    Path(path).write_text(json.dumps(plan, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({'status': plan['status'], 'source_commit': plan['source_commit']}))


def reconcile(path):
    plan = _plan(path, 'PREPARED_NOT_EXECUTED')
    described = aws('cloudformation', 'describe-change-set',
                    '--change-set-name', plan['change_set_arn'])
    validate_changes(described['Changes'])
    stack, _ = _stack()
    if (described.get('ExecutionStatus') != 'EXECUTE_COMPLETE' or
            described.get('StackId') != plan['stack_id'] or
            described.get('Changes') != plan['changes'] or
            stack['StackId'] != plan['stack_id'] or _version(stack) != plan['builder_version']):
        raise RuntimeError('Builder broker pin was not executed as prepared')
    plan['status'] = 'DEPLOYED_PENDING_VERIFICATION'
    Path(path).write_text(json.dumps(plan, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({'status': plan['status'], 'reconciled': True}))


def verify(path):
    plan = _plan(path, 'DEPLOYED_PENDING_VERIFICATION')
    stack, params = _stack()
    if (stack['StackId'] != plan['stack_id'] or _version(stack) != plan['builder_version'] or
            params.get('CodeSha256') != plan['code_sha256']):
        raise RuntimeError('Builder code or version changed')
    for arn in (plan['builder_version'], plan['builder_version'].rsplit(':', 1)[0]):
        _disabled(arn, plan['code_sha256'])
    _broker_disabled()
    role_policy = aws('iam', 'get-role-policy', '--role-name', ROLE,
                      '--policy-name', POLICY_NAME)['PolicyDocument']
    if isinstance(role_policy, str):
        from urllib.parse import unquote
        role_policy = json.loads(unquote(role_policy))
    expected = _template()['Resources']['BuilderRole']['Properties']['Policies'][1][
        'Fn::If'][1]['PolicyDocument']
    for statement in expected['Statement']:
        if statement.get('Sid') == 'OwnExactAcceptanceExecution':
            statement['Resource'] = f'arn:aws:dynamodb:{REGION}:{ACCOUNT}:table/tims-factory-role-executions'
    if role_policy != expected:
        raise RuntimeError('deployed Builder policy differs from pinned broker version 3')
    evidence = {'status': 'BUILDER_BROKER_V3_PIN_DISABLED_VERIFIED',
                'source_commit': plan['source_commit'],
                'builder_version': plan['builder_version'],
                'broker_target': BROKER, 'operational_execution_enabled': False,
                'provider_calls_by_verifier': 0}
    Path(path).with_name('builder-broker-v3-evidence.json').write_text(
        json.dumps(evidence, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(evidence, indent=2))


if __name__ == '__main__':
    if len(sys.argv) != 3 or sys.argv[1] not in {'prepare', 'execute', 'reconcile', 'verify'}:
        raise SystemExit('usage: prepare_builder_broker_v3.py prepare|execute|reconcile|verify PLAN_JSON')
    globals()[sys.argv[1]](sys.argv[2])
