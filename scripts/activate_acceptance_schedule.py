"""One scheduled commissioning delivery, zero retries; reconcile, never replay."""
from __future__ import annotations

import base64
import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import activate_acceptance_component as component
from prepare_role_deployment import ACCOUNT, REGION, aws, source
from stage_disabled_acceptance_config import assert_schedule, save
from verify_disabled_autonomy_schedule import INPUT, NAME, ROLE, TARGET
from verify_acceptance_staging_scope import verify_live_scope


def scheduler_iam():
    name = ROLE.rsplit('/', 1)[-1]
    trust = {'Version': '2012-10-17', 'Statement': [{'Effect': 'Allow',
        'Action': 'sts:AssumeRole', 'Principal': {'Service': 'scheduler.amazonaws.com'},
        'Condition': {'StringEquals': {'aws:SourceAccount': ACCOUNT},
            'ArnEquals': {'aws:SourceArn': f'arn:aws:scheduler:{REGION}:{ACCOUNT}:schedule-group/default'}}}]}
    role = aws('iam', 'get-role', '--role-name', name)['Role']
    policy_name = 'tims-software-factory-autonomy-scheduler-invoke'
    policy = {'Version': '2012-10-17', 'Statement': [{'Sid': 'InvokeExactAcceptanceControllerAlias',
        'Effect': 'Allow', 'Action': 'lambda:InvokeFunction', 'Resource': TARGET}]}
    if (component.normalize(role['AssumeRolePolicyDocument']) != component.normalize(trust) or
            aws('iam', 'list-attached-role-policies', '--role-name', name)['AttachedPolicies'] or
            aws('iam', 'list-role-policies', '--role-name', name)['PolicyNames'] != [policy_name] or
            component.normalize(aws('iam', 'get-role-policy', '--role-name', name,
                '--policy-name', policy_name)['PolicyDocument']) != component.normalize(policy)):
        raise RuntimeError('scheduler trust or invocation permission differs from exact reviewed scope')


def live_gate(path, *, now):
    plan = json.loads(Path(path).read_text())
    if plan.get('component') != 'controller' or plan.get('status') != 'COMPONENT_PUBLISHED_SCHEDULE_DISABLED':
        raise RuntimeError('all three published components are required before scheduling')
    _, template = component.checked(plan, live=False)
    component.published('controller', template, plan['before'], version=plan['version_arn'])
    for name in ('broker', 'builder'):
        previous = json.loads(Path(plan['predecessors'][name]).read_text())
        if previous.get('status') != 'COMPONENT_PUBLISHED_SCHEDULE_DISABLED':
            raise RuntimeError('predecessor deployment is incomplete')
        _, template = component.checked(previous, live=False)
        for key in ('activation_id', 'source_commit', 'contract_digest', 'starts_at', 'expires_at', 'job_version_id', 'provider_secret_arn'):
            if previous['binding'][key] != plan['binding'][key]:
                raise RuntimeError('component scopes differ')
        if (previous['job_base64'] != plan['job_base64'] or
                previous['before']['code_sha256'] != plan['before']['code_sha256'] or
                (name == 'builder' and previous['binding']['broker_version_arn'] != plan['binding']['broker_version_arn'])):
            raise RuntimeError('component package, job or broker pin differs')
        component.published(name, template, previous['before'],
            version=plan['binding'][name + '_version_arn'], check_alias=False)
    raw = base64.b64decode(plan['job_base64'], validate=True)
    verify_live_scope(plan['binding'], raw, now=now)
    scheduler_iam()
    return plan


def schedule_request(plan, *, run_at, now):
    document = json.loads(base64.b64decode(plan['job_base64'], validate=True))
    deadlines = [datetime.fromisoformat(plan['binding']['expires_at']),
                 datetime.fromisoformat(document['lease']['expires_at'])]
    deadlines += [datetime.fromtimestamp(document[key]['expires_at'], timezone.utc)
                  for key in ('capability_payload', 'review_payload')]
    if not now + timedelta(seconds=60) <= run_at < min(deadlines) - timedelta(minutes=5):
        raise RuntimeError('insufficient fresh scope for one scheduled delivery and bounded execution')
    return {'Name': NAME, 'GroupName': 'default', 'State': 'ENABLED',
        'ScheduleExpression': 'at(' + run_at.strftime('%Y-%m-%dT%H:%M:%S') + ')',
        'ScheduleExpressionTimezone': 'UTC', 'FlexibleTimeWindow': {'Mode': 'OFF'},
        'ActionAfterCompletion': 'NONE', 'Target': {'Arn': TARGET, 'RoleArn': ROLE,
            'Input': json.dumps(INPUT, sort_keys=True, separators=(',', ':')),
            'RetryPolicy': {'MaximumRetryAttempts': 0, 'MaximumEventAgeInSeconds': 60}}}


def prepare(controller_path, path):
    now = datetime.now(timezone.utc)
    controller = live_gate(controller_path, now=now)
    request = schedule_request(controller, run_at=(now + timedelta(minutes=3)).replace(microsecond=0), now=now)
    before = aws('scheduler', 'get-schedule', '--name', NAME)
    assert_schedule()
    plan = {'status': 'PREPARED_NOT_EXECUTED', 'source_commit': source(),
        'controller_path': str(Path(controller_path).resolve()), 'controller_sha256': component.sha(controller),
        'prepared_at': now.isoformat(), 'before': before, 'request': request}
    save(path, plan, exclusive=True)
    print(json.dumps({'status': plan['status'], 'schedule': request}))


def execute(path):
    plan = json.loads(Path(path).read_text())
    if plan['status'] != 'PREPARED_NOT_EXECUTED' or plan['source_commit'] != source():
        raise RuntimeError('schedule activation is single-attempt; reconcile an uncertain result')
    now = datetime.now(timezone.utc)
    controller = live_gate(plan['controller_path'], now=now)
    run_at = datetime.strptime(plan['request']['ScheduleExpression'], 'at(%Y-%m-%dT%H:%M:%S)').replace(tzinfo=timezone.utc)
    if (component.sha(controller) != plan['controller_sha256'] or
            schedule_request(controller, run_at=run_at, now=now) != plan['request'] or
            aws('scheduler', 'get-schedule', '--name', NAME) != plan['before']):
        raise RuntimeError('schedule or deployment changed after preparation')
    plan['status'] = 'ATTEMPTED_RECONCILE_REQUIRED'; save(path, plan)
    aws('scheduler', 'update-schedule', '--cli-input-json', json.dumps(plan['request']))
    reconcile(path)


def reconcile(path):
    plan = json.loads(Path(path).read_text())
    if plan['status'] not in {'ATTEMPTED_RECONCILE_REQUIRED', 'ONE_DELIVERY_SCHEDULED'}:
        raise RuntimeError('schedule activation was not attempted')
    if aws('sts', 'get-caller-identity')['Account'] != ACCOUNT:
        raise RuntimeError('wrong AWS account')
    actual = aws('scheduler', 'get-schedule', '--name', NAME)
    if any(actual.get(key) != value for key, value in plan['request'].items()):
        raise RuntimeError('schedule outcome differs; do not resubmit or invoke manually')
    plan['status'] = 'ONE_DELIVERY_SCHEDULED'; save(path, plan)
    print(json.dumps({'status': plan['status'], 'expression': actual['ScheduleExpression'],
                     'provider_outcome': 'NOT_YET_VERIFIED'}))


if __name__ == '__main__':
    if len(sys.argv) == 4 and sys.argv[1] == 'prepare':
        prepare(*sys.argv[2:])
    elif len(sys.argv) == 3 and sys.argv[1] in {'execute', 'reconcile'}:
        (execute if sys.argv[1] == 'execute' else reconcile)(sys.argv[2])
    else:
        raise SystemExit('use prepare CONTROLLER_PLAN PLAN | execute PLAN | reconcile PLAN')
