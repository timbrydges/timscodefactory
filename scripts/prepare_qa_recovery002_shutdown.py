"""Offline independent concurrency shutdown schedule; never deploy or arm."""
import json
from datetime import datetime,timezone
from factory_state.model import StateError
from prepare_qa_recovery002_disabled import FUNCTION

GROUP='tims-factory-qa-recovery-002-shutdown'
NAME='qa-recovery002-concurrency-zero'
ROLE=GROUP
STACK=GROUP+'-v2'
FUNCTION_ARN='arn:aws:lambda:ca-central-1:666730517561:function:'+FUNCTION
GROUP_ARN='arn:aws:scheduler:ca-central-1:666730517561:schedule-group/'+GROUP
ROLE_ARN='arn:aws:iam::666730517561:role/'+ROLE
TARGET='arn:aws:scheduler:::aws-sdk:lambda:putFunctionConcurrency'


def properties(deadline,*,now,armed=False):
    if (type(deadline) is not int or not isinstance(now,datetime) or now.tzinfo is None or now.utcoffset() is None or
            not 60<=deadline-now.timestamp()<=1800 or type(armed) is not bool):
        raise StateError('Shutdown deadline must be 1 to 30 minutes ahead')
    return {'Name':NAME,'GroupName':GROUP,'State':'ENABLED' if armed else 'DISABLED',
        'ScheduleExpression':'rate(1 minute)','ScheduleExpressionTimezone':'UTC',
        'StartDate':datetime.fromtimestamp(deadline,timezone.utc).isoformat(),
        'EndDate':datetime.fromtimestamp(deadline+900,timezone.utc).isoformat(),
        'FlexibleTimeWindow':{'Mode':'OFF'},'ActionAfterCompletion':'NONE',
        'Target':{'Arn':TARGET,'RoleArn':ROLE_ARN,
            'Input':json.dumps({'FunctionName':FUNCTION_ARN,'ReservedConcurrentExecutions':0},separators=(',',':')),
            'RetryPolicy':{'MaximumEventAgeInSeconds':60,'MaximumRetryAttempts':2}}}


def render(deadline,*,now,armed=False):
    schedule=properties(deadline,now=now,armed=armed)
    # Scheduler API supports this field, but the CloudFormation resource does not.
    # Omission preserves the default NONE; validate_armed still checks the API value.
    schedule.pop('ActionAfterCompletion')
    for field in ('StartDate','EndDate'):
        schedule[field]=datetime.fromisoformat(schedule[field]).strftime('%Y-%m-%dT%H:%M:%S.000Z')
    return {'AWSTemplateFormatVersion':'2010-09-09','Description':'Recovery-only concurrency shutdown; never invokes a function.',
        'Resources':{
            'ShutdownGroup':{'Type':'AWS::Scheduler::ScheduleGroup','Properties':{'Name':GROUP}},
            'ShutdownRole':{'Type':'AWS::IAM::Role','Properties':{'RoleName':ROLE,
                'AssumeRolePolicyDocument':{'Version':'2012-10-17','Statement':[{'Effect':'Allow',
                    'Principal':{'Service':'scheduler.amazonaws.com'},'Action':'sts:AssumeRole',
                    'Condition':{'StringEquals':{'aws:SourceAccount':'666730517561','aws:SourceArn':GROUP_ARN}}}]},
                'Policies':[{'PolicyName':'recovery002-concurrency-only','PolicyDocument':{'Version':'2012-10-17',
                    'Statement':[{'Effect':'Allow','Action':'lambda:PutFunctionConcurrency','Resource':FUNCTION_ARN}]}}]}},
            'ShutdownSchedule':{'Type':'AWS::Scheduler::Schedule','DependsOn':['ShutdownGroup','ShutdownRole'],'Properties':schedule}}}


def validate_armed(schedule,deadline,*,now):
    expected=properties(deadline,now=now,armed=True)
    # API timestamps are datetimes; CloudFormation inputs are ISO UTC strings.
    actual={key:schedule.get(key) for key in expected}
    for field in ('StartDate','EndDate'):
        if isinstance(actual[field],datetime):actual[field]=actual[field].astimezone(timezone.utc).isoformat()
    if actual!=expected:raise StateError('Independent recovery shutdown is missing, disarmed or changed')
    return {'status':'ARMED_CONFIGURATION_VERIFIED','deadline':deadline,'model_invocations':0}


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


def validate_preview(template,changes,deadline,*,now,armed=False):
    expected=render(deadline,now=now,armed=armed)
    if (template!=expected or changes.get('Status')!='CREATE_COMPLETE' or changes.get('ExecutionStatus')!='AVAILABLE' or
            changes.get('NextToken') or changes.get('Parameters') or not str(changes.get('StackId','')).startswith(
                'arn:aws:cloudformation:ca-central-1:666730517561:stack/'+STACK+'/')):
        raise StateError('Shutdown deployment preview differs')
    rows=changes.get('Changes',[]);seen=set()
    if len(rows)!=3:raise StateError('Shutdown preview must add exactly three resources')
    for row in rows:
        r=row.get('ResourceChange',{});name=r.get('LogicalResourceId')
        if (row.get('Type')!='Resource' or name not in expected['Resources'] or name in seen or
                r.get('Action')!='Add' or r.get('ResourceType')!=expected['Resources'][name]['Type']):
            raise StateError('Unexpected shutdown resource change')
        seen.add(name)
    return {'status':'SHUTDOWN_PREVIEW_NOT_EXECUTED','armed':armed,'model_invocations':0}
