"""Offline QA-only shutdown preview. Never deploy, arm or invoke a worker."""
import json
from datetime import datetime, timezone

import prepare_inspector_recovery001_shutdown as recovery
from factory_state.model import StateError

GROUP = 'tims-factory-pilot-002-qa-shutdown'
NAME = 'pilot002-qa-concurrency-zero'
ROLE = GROUP
STACK = GROUP
FUNCTION_ARN = 'arn:aws:lambda:ca-central-1:666730517561:function:tims-factory-pilot-002-qa'
GROUP_ARN = 'arn:aws:scheduler:ca-central-1:666730517561:schedule-group/' + GROUP
ROLE_ARN = 'arn:aws:iam::666730517561:role/' + ROLE


def properties(deadline, *, now, armed=False):
    # QA's free-tier allowance lasts at most five minutes. Runtime arming must
    # support that window; the initial disabled deployment retains its longer lead.
    if (type(deadline) is not int or not isinstance(now, datetime) or
            now.tzinfo is None or now.utcoffset() is None or type(armed) is not bool or
            not 60 <= deadline - now.timestamp() <= 1800):
        raise StateError('QA shutdown deadline must be 1 to 30 minutes ahead')
    return {'Name': NAME, 'GroupName': GROUP, 'State': 'ENABLED' if armed else 'DISABLED',
        'ScheduleExpression': 'rate(1 minute)', 'ScheduleExpressionTimezone': 'UTC',
        'StartDate': datetime.fromtimestamp(deadline, timezone.utc).isoformat(),
        'EndDate': datetime.fromtimestamp(deadline + 900, timezone.utc).isoformat(),
        'FlexibleTimeWindow': {'Mode': 'OFF'}, 'ActionAfterCompletion': 'NONE',
        'Target': {'Arn': recovery.TARGET, 'RoleArn': ROLE_ARN,
            'Input': json.dumps({'FunctionName': FUNCTION_ARN, 'ReservedConcurrentExecutions': 0},
                separators=(',', ':')),
            'RetryPolicy': {'MaximumEventAgeInSeconds': 60, 'MaximumRetryAttempts': 2}}}


def render(deadline, *, now, armed=False):
    result = recovery.render(deadline, now=now, armed=armed)
    result['Description'] = 'Pilot 002 QA-only concurrency shutdown; never invokes a function.'
    resources = result['Resources']
    resources['ShutdownGroup']['Properties']['Name'] = GROUP
    role = resources['ShutdownRole']['Properties']
    role['RoleName'] = ROLE
    role['AssumeRolePolicyDocument']['Statement'][0]['Condition']['StringEquals']['aws:SourceArn'] = GROUP_ARN
    role['Policies'][0]['PolicyName'] = 'pilot002-qa-concurrency-only'
    role['Policies'][0]['PolicyDocument']['Statement'][0]['Resource'] = FUNCTION_ARN
    schedule = properties(deadline, now=now, armed=armed)
    schedule.pop('ActionAfterCompletion')
    for field in ('StartDate', 'EndDate'):
        schedule[field] = datetime.fromisoformat(schedule[field]).strftime('%Y-%m-%dT%H:%M:%S.000Z')
    resources['ShutdownSchedule']['Properties'] = schedule
    return result


def validate_armed(schedule, deadline, *, now):
    expected = properties(deadline, now=now, armed=True)
    actual = {key: schedule.get(key) for key in expected}
    for field in ('StartDate', 'EndDate'):
        if isinstance(actual[field], datetime):
            actual[field] = actual[field].astimezone(timezone.utc).isoformat()
    if actual != expected:
        raise StateError('Independent QA shutdown is missing, disarmed or changed')
    return {'status': 'ARMED_QA_CONFIGURATION_VERIFIED', 'deadline': deadline, 'model_invocations': 0}


def validate_live_window(schedule, deadline, *, allowance_expires_at, now):
    """Check timing after separate signature verification; never extend an allowance.

    Leave one minute for Scheduler's execution precision. This is a configuration
    check, not proof of timely delivery or termination of an in-flight invocation.
    """
    result = validate_armed(schedule, deadline, now=now)
    if (type(allowance_expires_at) is not int or
            not now.timestamp() < allowance_expires_at <= now.timestamp() + 300 or
            deadline + 60 > allowance_expires_at):
        raise StateError('QA shutdown must fit inside the unexpired five-minute allowance')
    return {**result, 'allowance_expires_at': allowance_expires_at,
        'latest_nominal_first_execution': deadline + 60, 'execution_authorized': False}


def validate_preview(template, changes, deadline, *, now):
    # Initial installation must be disabled. Arming is a separate, bounded action.
    expected = render(deadline, now=now)
    if (template != expected or changes.get('Status') != 'CREATE_COMPLETE' or
            changes.get('ExecutionStatus') != 'AVAILABLE' or changes.get('NextToken') or
            changes.get('Parameters') or not str(changes.get('StackId', '')).startswith(
                'arn:aws:cloudformation:ca-central-1:666730517561:stack/' + STACK + '/')):
        raise StateError('QA shutdown deployment preview differs')
    rows = changes.get('Changes', [])
    seen = set()
    if len(rows) != 3:
        raise StateError('QA shutdown must add exactly three resources')
    for row in rows:
        resource = row.get('ResourceChange', {})
        name = resource.get('LogicalResourceId')
        if (row.get('Type') != 'Resource' or name not in expected['Resources'] or name in seen or
                resource.get('Action') != 'Add' or
                resource.get('ResourceType') != expected['Resources'][name]['Type']):
            raise StateError('Unexpected QA shutdown resource change')
        seen.add(name)
    return {'status': 'QA_SHUTDOWN_PREVIEW_NOT_EXECUTED', 'armed': False, 'model_invocations': 0}
