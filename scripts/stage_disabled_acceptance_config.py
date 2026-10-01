"""Stage environment settings only; never publish, enable, invoke or grant IAM.

Each plan updates one existing CloudFormation function. Published versions and
the controller alias remain unchanged. A failed execute requires reconciliation,
not another execute attempt. Receipt authenticity is a later activation gate.
"""
from __future__ import annotations

import base64
import copy
import hashlib
import json
import re
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

from prepare_acceptance_activation_bundle import build_activation_bundle
from prepare_role_deployment import ACCOUNT, ROOT, aws, source
from verify_disabled_autonomy_schedule import INPUT, NAME, ROLE, TARGET

COMPONENTS = {
    'builder': ('tims-factory-roles', 'infra/roles/functions.cloudformation.json',
                'BuilderFunction', 'tims-factory-builder', 'FACTORY_OPERATIONAL_EXECUTION_ENABLED'),
    'broker': ('tims-factory-acceptance-broker', 'infra/acceptance/broker-canary.cloudformation.json',
               'BrokerFunction', 'tims-factory-provider-broker', 'FACTORY_ACCEPTANCE_BROKER_ENABLED'),
    'controller': ('tims-factory-autonomy-controller-disabled',
        'infra/acceptance/controller-disabled.cloudformation.json', 'ControllerFunction',
        'tims-software-factory-autonomy-controller', 'FACTORY_AUTONOMY_CONTROLLER_ENABLED'),
}


def canary_bundle(component, nonce):
    if component not in COMPONENTS or not isinstance(nonce, str) or not re.fullmatch('[0-9a-f]{32}', nonce):
        raise RuntimeError('invalid configuration canary')
    return {'status': 'PREPARED_DISABLED_NOT_DEPLOYED', 'activation_authorized': False,
        'model_calls_authorized': 0, 'environment_updates': {component: {
            COMPONENTS[component][4]: 'false', 'FACTORY_CONFIGURATION_CANARY': nonce}}}


def render(component, bundle):
    if component not in COMPONENTS:
        raise RuntimeError('unknown acceptance component')
    _, relative, logical, _, flag = COMPONENTS[component]
    baseline = json.loads((ROOT / relative).read_text())
    updates = bundle['environment_updates'][component]
    if (bundle.get('status') != 'PREPARED_DISABLED_NOT_DEPLOYED' or
            bundle.get('activation_authorized') is not False or
            bundle.get('model_calls_authorized') != 0 or updates.get(flag) != 'false'):
        raise RuntimeError('only a disabled preparation bundle may be staged')
    proposed = copy.deepcopy(baseline)
    proposed['Resources'][logical]['Properties']['Environment']['Variables'].update(updates)
    return baseline, proposed


def validate_changes(component, changes):
    logical = COMPONENTS[component][2]
    if len(changes) != 1:
        raise RuntimeError('staging may modify only one function environment')
    change = changes[0]['ResourceChange']
    expected_detail = {'Target': {'Attribute': 'Properties', 'Name': 'Environment',
        'RequiresRecreation': 'Never'}, 'Evaluation': 'Static', 'ChangeSource': 'DirectModification'}
    if (change.get('LogicalResourceId') != logical or
            change.get('ResourceType') != 'AWS::Lambda::Function' or
            change.get('Action') != 'Modify' or change.get('Replacement') != 'False' or
            change.get('Scope') != ['Properties'] or change.get('Details') != [expected_detail]):
        raise RuntimeError('staging change set exceeds the exact environment-only boundary')


def assert_schedule():
    schedule = aws('scheduler', 'get-schedule', '--name', NAME)
    target = schedule.get('Target', {})
    if (schedule.get('Name') != NAME or schedule.get('State') != 'DISABLED' or
            schedule.get('ScheduleExpression') != 'rate(15 minutes)' or
            schedule.get('ScheduleExpressionTimezone') != 'UTC' or
            schedule.get('FlexibleTimeWindow') != {'Mode': 'OFF'} or
            target.get('Arn') != TARGET or target.get('RoleArn') != ROLE or
            json.loads(target.get('Input', 'null')) != INPUT or
            target.get('RetryPolicy') != {'MaximumRetryAttempts': 0, 'MaximumEventAgeInSeconds': 60}):
        raise RuntimeError('acceptance schedule is not the exact disabled no-retry target')


def snapshot(component, template):
    stack_name, _, logical, function, flag = COMPONENTS[component]
    stack = aws('cloudformation', 'describe-stacks', '--stack-name', stack_name)['Stacks'][0]
    if stack['StackStatus'] not in {'CREATE_COMPLETE', 'UPDATE_COMPLETE'}:
        raise RuntimeError('component stack is not stable')
    deployed = aws('cloudformation', 'get-template', '--stack-name', stack_name)['TemplateBody']
    if isinstance(deployed, str):
        deployed = json.loads(deployed)
    if deployed != template:
        raise RuntimeError('component template differs from exact reviewed stage')
    params = {p['ParameterKey']: p['ParameterValue'] for p in stack['Parameters']}
    expected_env = {}
    for key, value in template['Resources'][logical]['Properties']['Environment']['Variables'].items():
        if isinstance(value, dict):
            reference = value['Ref']
            value = (params[reference] if reference in params else
                     template['Resources'][reference]['Properties']['TableName'])
        expected_env[key] = value
    config = aws('lambda', 'get-function-configuration', '--function-name', function)
    properties = template['Resources'][logical]['Properties']
    role_logical = properties['Role']['Fn::GetAtt'][0]
    role_name = template['Resources'][role_logical]['Properties']['RoleName']
    if (config.get('State') != 'Active' or config.get('LastUpdateStatus') != 'Successful' or
            config.get('CodeSha256') != params['CodeSha256'] or
            config.get('Role') != f'arn:aws:iam::{ACCOUNT}:role/{role_name}' or
            config.get('Handler') != properties['Handler'] or
            config.get('Timeout') != properties['Timeout'] or
            config.get('Environment', {}).get('Variables') != expected_env or
            expected_env.get(flag) != 'false'):
        raise RuntimeError('component runtime differs or is not disabled')
    alias = aws('lambda', 'get-alias', '--function-name', COMPONENTS['controller'][3],
                '--name', 'acceptance')
    if alias.get('AliasArn') != TARGET or alias.get('RoutingConfig', {}).get('AdditionalVersionWeights'):
        raise RuntimeError('controller alias differs from the unweighted acceptance target')
    return {'stack_id': stack['StackId'], 'parameters': params,
        'outputs': sorted(stack.get('Outputs', []), key=lambda x: x['OutputKey']),
        'revision_id': config['RevisionId'], 'role': config['Role'],
        'code_sha256': config['CodeSha256'], 'alias': alias}


def save(path, plan, *, exclusive=False):
    with Path(path).open('x' if exclusive else 'w', encoding='utf-8', newline='\n') as output:
        output.write(json.dumps(plan, sort_keys=True, indent=2) + '\n')


def checked(path, *, current_time=True):
    plan = json.loads(Path(path).read_text())
    if plan['tool_source_commit'] != source() or aws('sts', 'get-caller-identity')['Account'] != ACCOUNT:
        raise RuntimeError('staging tool source or AWS account changed')
    now = datetime.now(timezone.utc) if current_time else datetime.fromisoformat(plan['prepared_at'])
    mode = plan.get('mode')
    if mode in {'canary', 'canary_cleanup'}:
        bundle = canary_bundle(plan['component'], plan['canary_nonce'])
    elif mode == 'binding':
        bundle = build_activation_bundle(plan['binding'], base64.b64decode(plan['job_base64'], validate=True), now=now)
    else:
        raise RuntimeError('unknown staging mode')
    baseline, proposed = render(plan['component'], bundle)
    if mode == 'canary_cleanup':
        baseline, proposed = proposed, baseline
    if plan['bundle'] != bundle or plan['template_sha256'] != hashlib.sha256(
            json.dumps(proposed, sort_keys=True).encode()).hexdigest():
        raise RuntimeError('staging inputs changed')
    assert_schedule()
    return plan, baseline, proposed


def prepare(component, binding_path, job_path, path):
    now = datetime.now(timezone.utc)
    binding = json.loads(Path(binding_path).read_text())
    raw = Path(job_path).read_bytes()
    bundle = build_activation_bundle(binding, raw, now=now)
    prepare_bundle(component, bundle, path, now=now, mode='binding',
                   binding=binding, job_base64=base64.b64encode(raw).decode())


def prepare_bundle(component, bundle, path, *, now, mode, **material):
    baseline, proposed = render(component, bundle)
    if mode == 'canary_cleanup':
        baseline, proposed = proposed, baseline
    commit = source()
    if aws('sts', 'get-caller-identity')['Account'] != ACCOUNT:
        raise RuntimeError('wrong AWS account')
    assert_schedule()
    before = snapshot(component, baseline)
    plan = {'status': 'PREPARING', 'component': component, 'tool_source_commit': commit,
        'prepared_at': now.isoformat(), 'mode': mode, **material, 'bundle': bundle, 'before': before,
        'template_sha256': hashlib.sha256(json.dumps(proposed, sort_keys=True).encode()).hexdigest()}
    save(path, plan, exclusive=True)
    template_path = Path(path).with_suffix('.template.json')
    save(template_path, proposed, exclusive=True)
    created = aws('cloudformation', 'create-change-set', '--stack-name', COMPONENTS[component][0],
        '--change-set-name', 'disabled-config-' + uuid.uuid4().hex,
        '--change-set-type', 'UPDATE', '--template-body', 'file://' + str(template_path.resolve()),
        '--parameters', json.dumps([{'ParameterKey': key, 'UsePreviousValue': True}
                                    for key in before['parameters']]),
        '--capabilities', 'CAPABILITY_NAMED_IAM')
    plan['change_set_arn'] = created['Id']
    save(path, plan)
    aws('cloudformation', 'wait', 'change-set-create-complete', '--change-set-name', created['Id'])
    change = aws('cloudformation', 'describe-change-set', '--change-set-name', created['Id'])
    validate_changes(component, change['Changes'])
    plan.update(status='PREPARED_NOT_EXECUTED', changes=change['Changes'])
    save(path, plan)
    print(json.dumps({'status': plan['status'], 'component': component, 'model_calls': 0}))


def prepare_canary(component, path):
    nonce = uuid.uuid4().hex
    prepare_bundle(component, canary_bundle(component, nonce), path,
        now=datetime.now(timezone.utc), mode='canary', canary_nonce=nonce)


def prepare_cleanup(canary_path, path):
    verify(canary_path)
    plan, _, _ = checked(canary_path, current_time=False)
    if plan['mode'] != 'canary':
        raise RuntimeError('cleanup requires a verified configuration canary')
    prepare_bundle(plan['component'], plan['bundle'], path,
        now=datetime.now(timezone.utc), mode='canary_cleanup', canary_nonce=plan['canary_nonce'])


def check_change(plan, execution_status):
    change = aws('cloudformation', 'describe-change-set', '--change-set-name', plan['change_set_arn'])
    validate_changes(plan['component'], change['Changes'])
    if (change.get('Status') != 'CREATE_COMPLETE' or change.get('ExecutionStatus') != execution_status or
            change.get('StackId') != plan['before']['stack_id'] or change['Changes'] != plan['changes'] or
            {p['ParameterKey']: p['ParameterValue'] for p in change['Parameters']} != plan['before']['parameters']):
        raise RuntimeError('staging change set differs from reviewed plan')
    actual = aws('cloudformation', 'get-template', '--change-set-name', plan['change_set_arn'])['TemplateBody']
    if isinstance(actual, str):
        actual = json.loads(actual)
    if hashlib.sha256(json.dumps(actual, sort_keys=True).encode()).hexdigest() != plan['template_sha256']:
        raise RuntimeError('staging change set template changed')


def execute(path):
    plan, baseline, _ = checked(path)
    if plan['status'] != 'PREPARED_NOT_EXECUTED':
        raise RuntimeError('execute is single-attempt; reconcile an uncertain result')
    if snapshot(plan['component'], baseline) != plan['before']:
        raise RuntimeError('component or controller alias changed since preparation')
    check_change(plan, 'AVAILABLE')
    plan['status'] = 'EXECUTION_ATTEMPTED_RECONCILE_REQUIRED'
    save(path, plan)
    aws('cloudformation', 'execute-change-set', '--change-set-name', plan['change_set_arn'])
    aws('cloudformation', 'wait', 'stack-update-complete', '--stack-name', COMPONENTS[plan['component']][0])
    verify(path)


def verify(path):
    # Read-only reconciliation remains possible after the receipts expire.
    plan, _, proposed = checked(path, current_time=False)
    if plan['status'] not in {'EXECUTION_ATTEMPTED_RECONCILE_REQUIRED', 'DISABLED_CONFIGURATION_STAGED'}:
        raise RuntimeError('configuration staging has not been attempted')
    check_change(plan, 'EXECUTE_COMPLETE')
    after = snapshot(plan['component'], proposed)
    if {k: v for k, v in after.items() if k != 'revision_id'} != {
            k: v for k, v in plan['before'].items() if k != 'revision_id'}:
        raise RuntimeError('staging altered code, role, parameters, published versions or alias')
    plan['status'] = 'DISABLED_CONFIGURATION_STAGED'
    save(path, plan)
    print(json.dumps({'status': plan['status'], 'component': plan['component'],
        'mode': plan['mode'],
        'model_calls': 0, 'activation_authorized': False, 'published_versions_changed': False}))


if __name__ == '__main__':
    if len(sys.argv) == 6 and sys.argv[1] == 'prepare':
        prepare(*sys.argv[2:])
    elif len(sys.argv) == 4 and sys.argv[1] in {'prepare-canary', 'prepare-cleanup'}:
        (prepare_canary if sys.argv[1] == 'prepare-canary' else prepare_cleanup)(*sys.argv[2:])
    elif len(sys.argv) == 3 and sys.argv[1] in {'execute', 'verify', 'reconcile'}:
        (execute if sys.argv[1] == 'execute' else verify)(sys.argv[2])
    else:
        raise SystemExit('use prepare COMPONENT BINDING JOB PLAN | prepare-canary COMPONENT PLAN | '
                         'prepare-cleanup CANARY_PLAN PLAN | execute PLAN | verify PLAN | reconcile PLAN')
