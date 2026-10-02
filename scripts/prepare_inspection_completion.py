"""Reviewable, reversible controller-only configuration for model-free import.

Deploy the clean disabled code package first. This tool never invokes a model,
the controller, or a scheduler. Restore removes all temporary state access.
"""
import copy
import json
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

from prepare_role_deployment import ACCOUNT, REGION, ROOT, aws, source
from prepare_disabled_autonomy_controller import STACK, TEMPLATE, FUNCTION, ROLE, validate_template
from stage_disabled_acceptance_config import assert_schedule
from activate_acceptance_component import verify_iam
from factory_runtime.inspection_completion import ENABLED, EXPIRY, validate_bundle


def templates():
    validate_template()
    baseline = json.loads(TEMPLATE.read_bytes())
    proposed = copy.deepcopy(baseline)
    resources = proposed['Resources']
    resources['ControllerFunction']['Properties']['Environment']['Variables'][ENABLED] = 'true'
    resources['ControllerVersion']['Properties']['Description'] = 'model-free-inspector-014-import'
    resources['ControllerRole']['Properties']['Policies'].append({
        'PolicyName': 'inspection-014-import-only', 'PolicyDocument': {
            'Version': '2012-10-17', 'Statement': [{
                'Effect': 'Allow', 'Action': ['dynamodb:GetItem', 'dynamodb:PutItem', 'dynamodb:UpdateItem'],
                'Resource': f'arn:aws:dynamodb:{REGION}:{ACCOUNT}:table/tims-software-factory-state',
                'Condition': {
                    'ForAllValues:StringEquals': {'dynamodb:LeadingKeys': [
                        'FACTORY#tims-software-factory#TASK#deterministic-text-fingerprint']},
                    'DateLessThan': {'aws:CurrentTime': EXPIRY}}}]}})
    return baseline, proposed


def validate_changes(changes):
    expected = {'ControllerRole': ('AWS::IAM::Role', 'False', {'Policies'}),
        'ControllerFunction': ('AWS::Lambda::Function', 'False', {'Environment', 'Role'}),
        'ControllerVersion': ('AWS::Lambda::Version', 'True', {'Description', 'FunctionName'}),
        'AcceptanceAlias': ('AWS::Lambda::Alias', 'False', {'FunctionVersion', 'FunctionName'})}
    if len(changes) != 4 or {x['ResourceChange']['LogicalResourceId'] for x in changes} != set(expected):
        raise RuntimeError('completion change set has unexpected resources')
    for entry in changes:
        item = entry['ResourceChange']
        kind, replacement, properties = expected[item['LogicalResourceId']]
        if (item.get('Action') != 'Modify' or item.get('ResourceType') != kind or
                item.get('Replacement') != replacement or item.get('Scope') != ['Properties'] or
                not item.get('Details') or any(
                    d['Target'].get('Attribute') != 'Properties' or
                    d['Target'].get('Name') not in properties for d in item['Details'])):
            raise RuntimeError('completion change set exceeds exact configuration boundary')


def snapshot(expected):
    if aws('sts', 'get-caller-identity')['Account'] != ACCOUNT:
        raise RuntimeError('wrong account')
    assert_schedule()
    stack = aws('cloudformation', 'describe-stacks', '--stack-name', STACK)['Stacks'][0]
    deployed = aws('cloudformation', 'get-template', '--stack-name', STACK)['TemplateBody']
    if isinstance(deployed, str): deployed = json.loads(deployed)
    if stack['StackStatus'] not in {'CREATE_COMPLETE', 'UPDATE_COMPLETE'} or deployed != expected:
        raise RuntimeError('controller stack/template drifted')
    params = {p['ParameterKey']: p['ParameterValue'] for p in stack['Parameters']}
    verify_iam('controller', expected, params)
    outputs = {x['OutputKey']: x['OutputValue'] for x in stack['Outputs']}
    version = outputs['ControllerVersionArn']
    alias = aws('lambda', 'get-alias', '--function-name', FUNCTION, '--name', 'acceptance')
    config = aws('lambda', 'get-function-configuration', '--function-name', version)
    env = expected['Resources']['ControllerFunction']['Properties']['Environment']['Variables']
    latest = aws('lambda', 'get-function-configuration', '--function-name', FUNCTION)
    for actual in (config, latest):
        if (actual.get('Environment', {}).get('Variables') != env or
                actual.get('CodeSha256') != params['CodeSha256'] or
                actual.get('Role') != f'arn:aws:iam::{ACCOUNT}:role/{ROLE}' or
                actual.get('State') != 'Active' or actual.get('LastUpdateStatus', 'Successful') != 'Successful'):
            raise RuntimeError('controller code, flags or role drifted')
    if alias['FunctionVersion'] != version.rsplit(':', 1)[1] or alias.get('RoutingConfig', {}).get('AdditionalVersionWeights'):
        raise RuntimeError('controller alias drifted')
    return {'stack_id': stack['StackId'], 'version': version, 'parameters': params}


def prepare(mode, path):
    if mode not in {'enable', 'restore'}: raise RuntimeError('invalid completion mode')
    commit = source()
    baseline, proposed = templates()
    if mode == 'enable': validate_bundle(ROOT, datetime.now(timezone.utc))
    before, after = (baseline, proposed) if mode == 'enable' else (proposed, baseline)
    state = snapshot(before)
    if not state['parameters']['ArtifactKey'].startswith('factory-autonomy-controller-packages/' + commit + '/'):
        raise RuntimeError('deploy this exact disabled controller package first')
    plan_path = Path(path)
    if plan_path.exists(): raise RuntimeError('plan already exists; inspect instead of retrying')
    template_path = plan_path.with_suffix('.template.json')
    template_path.write_text(json.dumps(after, indent=2) + '\n')
    params = [{'ParameterKey': k, 'UsePreviousValue': True} for k in state['parameters']]
    created = aws('cloudformation', 'create-change-set', '--stack-name', STACK,
        '--change-set-name', 'inspection-import-' + mode + '-' + uuid.uuid4().hex[:12],
        '--change-set-type', 'UPDATE', '--template-body', 'file://' + str(template_path.resolve()),
        '--parameters', json.dumps(params), '--capabilities', 'CAPABILITY_NAMED_IAM')
    plan = {'mode': mode, 'source_commit': commit, 'before': state, 'change_set_arn': created['Id'],
            'status': 'PREPARING', 'model_calls': 0}
    plan_path.write_text(json.dumps(plan, indent=2) + '\n')
    aws('cloudformation', 'wait', 'change-set-create-complete', '--change-set-name', created['Id'])
    described = aws('cloudformation', 'describe-change-set', '--change-set-name', created['Id'])
    validate_changes(described['Changes'])
    plan.update(status='PREPARED', changes=described['Changes'])
    plan_path.write_text(json.dumps(plan, indent=2) + '\n')
    print(json.dumps(plan, indent=2))


def execute(path):
    plan = json.loads(Path(path).read_bytes())
    if plan['status'] != 'PREPARED' or plan['source_commit'] != source():
        raise RuntimeError('plan not prepared at this exact clean source')
    baseline, proposed = templates()
    if plan['mode'] == 'enable': validate_bundle(ROOT, datetime.now(timezone.utc))
    if snapshot(baseline if plan['mode'] == 'enable' else proposed) != plan['before']:
        raise RuntimeError('controller changed since preparation')
    described = aws('cloudformation', 'describe-change-set', '--change-set-name', plan['change_set_arn'])
    validate_changes(described['Changes'])
    if (described['Changes'] != plan['changes'] or described['ExecutionStatus'] != 'AVAILABLE' or
            described['StackId'] != plan['before']['stack_id']):
        raise RuntimeError('change set drifted')
    plan['status'] = 'ATTEMPTED_RECONCILE_ONLY'
    Path(path).write_text(json.dumps(plan, indent=2) + '\n')
    aws('cloudformation', 'execute-change-set', '--change-set-name', plan['change_set_arn'])
    aws('cloudformation', 'wait', 'stack-update-complete', '--stack-name', STACK)
    verify(path)


def verify(path):
    plan = json.loads(Path(path).read_bytes())
    if plan['status'] not in {'ATTEMPTED_RECONCILE_ONLY', 'VERIFIED'} or plan['source_commit'] != source():
        raise RuntimeError('only an attempted deployment can be reconciled')
    baseline, proposed = templates()
    described = aws('cloudformation', 'describe-change-set', '--change-set-name', plan['change_set_arn'])
    if described['ExecutionStatus'] != 'EXECUTE_COMPLETE' or described['Changes'] != plan['changes']:
        raise RuntimeError('deployment not complete')
    result = snapshot(proposed if plan['mode'] == 'enable' else baseline)
    if result['parameters'] != plan['before']['parameters'] or result['stack_id'] != plan['before']['stack_id']:
        raise RuntimeError('artifact or stack changed')
    plan.update(status='VERIFIED', after=result)
    Path(path).write_text(json.dumps(plan, indent=2) + '\n')
    print(json.dumps({'status': 'VERIFIED', 'mode': plan['mode'], 'version': result['version'], 'model_calls': 0}))


if __name__ == '__main__':
    if len(sys.argv) == 4 and sys.argv[1] == 'prepare': prepare(sys.argv[2], sys.argv[3])
    elif len(sys.argv) == 3 and sys.argv[1] in {'execute', 'verify'}:
        {'execute': execute, 'verify': verify}[sys.argv[1]](sys.argv[2])
    else: raise SystemExit('use prepare enable|restore PLAN | execute PLAN | verify PLAN')
