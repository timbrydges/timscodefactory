"""One exact owner-signed Inspector call; no retry, verified disabled rollback."""
import sys,json,time,hashlib
from pathlib import Path
from datetime import datetime,timezone
import boto3
from botocore.config import Config

if not __debug__:raise RuntimeError('Safety assertions require normal Python execution')

root=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(root/'src'),str(root/'scripts')]
from factory_state.scope import canonical
from factory_state.signers import validate_trusted_signers
from factory_runtime.pilot002_authorization import verify
from factory_runtime.pilot002_protocols import request_bytes
from factory_runtime.pilot002_packets import digest
from factory_runtime.pilot002_attempts import key,TABLE

from prepare_pilot002_inspector_live import validate, PLAN
import argparse
parser=argparse.ArgumentParser(description='Execute the separately approved Inspector plan once; always disable afterward')
parser.add_argument('allowance',type=Path);parser.add_argument('output_directory',type=Path)
parser.add_argument('--approved-plan-digest',required=True);parser.add_argument('--approved-change-set',required=True)
parser.add_argument('--signing-workflow-run',required=True,type=int)
args=parser.parse_args()
assert args.signing_workflow_run>0
assert args.approved_plan_digest==PLAN
plan=json.loads((root/'factory/evidence/pilot-002-inspector-live-review-candidate.json').read_bytes())
proof=json.loads((root/'factory/evidence/pilot-002-inspector-live-preview.json').read_bytes())
assert args.approved_change_set==proof['change_set_arn']
assert digest(plan)==PLAN and proof['plan_digest']==PLAN
envelope=json.loads(args.allowance.read_bytes())
now=datetime.now(timezone.utc)
assert envelope['payload']==plan['allowance_payload']
assert now.timestamp()<envelope['payload']['expires_at']-600
builder_response=__import__('base64').b64decode(plan['activation']['builder_response_base64'],validate=True)
review_context={'builder_response':builder_response,'candidate_commit':plan['activation']['candidate_commit']}
assert args.output_directory.is_dir()
if (args.output_directory/'inspector-execution-marker.json').exists():
    raise FileExistsError('Inspector execution already started; reconcile without retry')
def check_signature():
    now=datetime.now(timezone.utc)
    return verify(envelope,root=root,role='inspector',request_bytes=request_bytes(root,role='inspector',**review_context),**review_context,
        source_commit=plan['activation']['source_commit'],pricing=plan['pricing'],readiness=plan['activation']['readiness'],
        trusted_keys=validate_trusted_signers(plan['activation']['signer_registry'],now=now),now=now)
check_signature()
config=Config(retries={'total_max_attempts':1},connect_timeout=5,read_timeout=210)
s=boto3.Session(region_name='ca-central-1')
cf=s.client('cloudformation',config=config);lam=s.client('lambda',config=config);db=s.client('dynamodb',config=config)
assert s.client('sts',config=config).get_caller_identity()['Account']=='666730517561'
stack=proof['stack_id'];name='tims-factory-pilot-002-inspector'
def template(**kwargs):
    value=cf.get_template(**kwargs)['TemplateBody']
    return json.loads(value) if isinstance(value,str) else value
assert template(StackName=stack)==proof['rollback_template']
assert template(ChangeSetName=proof['change_set_arn'])==proof['template']
c=cf.describe_change_set(ChangeSetName=proof['change_set_arn'])
validate(proof['template'],c,proof['package'],proof['code'])
artifact=s.client('s3',config=config).get_object(Bucket=proof['code']['S3Bucket'],Key=proof['code']['S3Key'],VersionId=proof['code']['S3ObjectVersion'])
assert artifact['VersionId']==proof['code']['S3ObjectVersion']
package_bytes=artifact['Body'].read(5000001)
assert len(package_bytes)==proof['package']['zip_bytes'] and hashlib.sha256(package_bytes).hexdigest()==proof['package']['sha256']
assert s.client('lambda',config=config).get_account_settings()['AccountLimit']['UnreservedConcurrentExecutions']>=1
mappings=lam.list_event_source_mappings(FunctionName=name)
assert mappings['EventSourceMappings']==[] and not mappings.get('NextMarker')
rules=s.client('events',config=config).list_rule_names_by_target(TargetArn='arn:aws:lambda:ca-central-1:666730517561:function:'+name)
assert rules['RuleNames']==[] and not rules.get('NextToken')
aliases=lam.list_aliases(FunctionName=name)
assert aliases['Aliases']==[] and not aliases.get('NextMarker')
scheduler=s.client('scheduler',config=config)
for page in scheduler.get_paginator('list_schedules').paginate():
    for schedule in page.get('Schedules',[]):
        item=scheduler.get_schedule(Name=schedule['Name'],GroupName=schedule['GroupName'])
        target=item['Target']
        assert name not in target['Arn'] and name not in target.get('Input','')
for operation in ('get_policy','get_function_url_config'):
    try:getattr(lam,operation)(FunctionName=name)
    except lam.exceptions.ResourceNotFoundException:pass
    else:raise RuntimeError('Unexpected invocation surface')
for role in ('builder','inspector','qa'):
    f=lam.get_function_configuration(FunctionName='tims-factory-pilot-002-'+role)
    assert f['Environment']['Variables']['FACTORY_PILOT002_EXECUTION_ENABLED']=='false'
    assert lam.get_function_concurrency(FunctionName=f['FunctionName'])['ReservedConcurrentExecutions']==0
    if role!='builder':assert not db.get_item(TableName=TABLE,Key=key(role),ConsistentRead=True).get('Item')
report={'status':'EXECUTION_STARTED','started_at':now.isoformat(),'signing_workflow_run':args.signing_workflow_run,
    'change_set_arn':proof['change_set_arn'],'plan_digest':digest(plan),'lambda_requests':0,'shutdown_verified':False}
report_path=args.output_directory/'inspector-report.json'
def save():report_path.write_text(json.dumps(report,indent=2)+'\n')
with (args.output_directory/'inspector-execution-marker.json').open('x') as marker:json.dump(report,marker)
save()
try:
    cf.execute_change_set(ChangeSetName=proof['change_set_arn'],ClientRequestToken='approved-inspector-shared-359-20261004')
    print('APPROVED ACTIVATION SUBMITTED ONCE',flush=True)
    cf.get_waiter('stack_update_complete').wait(StackName=stack,WaiterConfig={'Delay':3,'MaxAttempts':60})
    assert template(StackName=stack)==proof['template']
    f=lam.get_function_configuration(FunctionName=name)
    assert f['CodeSha256']==proof['package']['code_sha256'] and f['LastUpdateStatus']=='Successful'
    assert f['Handler']=='factory_runtime.pilot002_entrypoint.handler' and f['Timeout']==180
    assert f['Environment']['Variables']==proof['template']['Resources']['InspectorFunction']['Properties']['Environment']['Variables']
    assert 'ReservedConcurrentExecutions' not in lam.get_function_concurrency(FunctionName=name)
    check_signature();assert time.time()<envelope['payload']['expires_at']-240
    assert not db.get_item(TableName=TABLE,Key=key('inspector'),ConsistentRead=True).get('Item')
    event=canonical({'kind':'pilot002_run_once','allowance':envelope})
    with (args.output_directory/'inspector-invocation-marker.json').open('x') as marker:
        json.dump({'event_sha256':hashlib.sha256(event).hexdigest(),'submitted_at':datetime.now(timezone.utc).isoformat(),'no_retry':True},marker)
    report['lambda_requests']=1;report['status']='INVOCATION_SUBMITTED_NO_RETRY';save()
    print('SINGLE INSPECTOR INVOCATION SUBMITTED - NEVER RETRY',flush=True)
    response=lam.invoke(FunctionName=name,InvocationType='RequestResponse',LogType='None',Payload=event)
    raw=response['Payload'].read(262145);assert len(raw)<=262144
    (args.output_directory/'inspector-result.json').write_bytes(raw)
    report.update(lambda_status=response['StatusCode'],function_error=response.get('FunctionError'),
        response_sha256=hashlib.sha256(raw).hexdigest(),response_bytes=len(raw),status='RESPONSE_RECEIVED')
    result=json.loads(raw)
    if not response.get('FunctionError'):
        assert result['status']=='PILOT002_COMPLETED_UNSIGNED'
        report.update(result_status=result['status'],actual_micro_usd=result['actual_micro_usd'],transport_invocations=result['transport_invocations'])
    save();print('RESPONSE STORED; RESTORING DISABLED STATE',flush=True)
except Exception as error:
    report.update(status='STOPPED_NO_RETRY',error_type=type(error).__name__);save()
    print('EXECUTION STOPPED; NO RETRY; RESTORING DISABLED STATE',flush=True)
finally:
    errors=[]
    try:
        # Wait for an uncertain stack operation before applying the final off switch.
        for _ in range(90):
            status=cf.describe_stacks(StackName=stack)['Stacks'][0]['StackStatus']
            if not status.endswith('_IN_PROGRESS'):break
            time.sleep(2)
        else:raise RuntimeError('Stack did not settle')
    except Exception as error:errors.append('stack_settle:'+type(error).__name__)
    try:lam.put_function_concurrency(FunctionName=name,ReservedConcurrentExecutions=0)
    except Exception as error:errors.append('concurrency_shutdown:'+type(error).__name__)
    try:
        if template(StackName=stack)!=proof['rollback_template']:
            cf.update_stack(StackName=stack,TemplateBody=json.dumps(proof['rollback_template']),
                Capabilities=['CAPABILITY_NAMED_IAM'],ClientRequestToken='restore-disabled-after-inspector-359')
            cf.get_waiter('stack_update_complete').wait(StackName=stack,WaiterConfig={'Delay':3,'MaxAttempts':60})
        assert template(StackName=stack)==proof['rollback_template']
        assert cf.describe_stacks(StackName=stack)['Stacks'][0]['StackStatus'] in ('UPDATE_COMPLETE','UPDATE_ROLLBACK_COMPLETE')
        for role in ('builder','inspector','qa'):
            f=lam.get_function_configuration(FunctionName='tims-factory-pilot-002-'+role)
            expected=proof['rollback_template']['Resources'][role.title()+'Function']['Properties']
            assert f['Environment']['Variables']==expected['Environment']['Variables']
            assert f['Handler']==expected['Handler'] and f['Timeout']==expected['Timeout']
            assert lam.get_function_concurrency(FunctionName=f['FunctionName'])['ReservedConcurrentExecutions']==0
            code='bfxa39U+CrnS05GTMT4DgHIC8KKWVHAxKbvgrcP37M4=' if role=='builder' else 'db7WTGzE+2ZpU064Y8Jt4DP89yDL+tzU/4U0E4OsAO4='
            assert f['CodeSha256']==code and f['LastUpdateStatus']=='Successful'
        report['shutdown_verified']=True
    except Exception as error:errors.append('rollback_verification:'+type(error).__name__)
    report['shutdown_errors']=errors
    try:report['attempt_rows']={role:db.get_item(TableName=TABLE,Key=key(role),ConsistentRead=True).get('Item') for role in ('builder','inspector','qa')}
    except Exception as error:report['reconciliation_error']=type(error).__name__
    report['finished_at']=datetime.now(timezone.utc).isoformat();save()
    print(json.dumps({k:v for k,v in report.items() if k!='attempt_rows'},indent=2),flush=True)
