"""Execute an exact separately approved recovery preview once, then restore disabled state."""
import argparse
import hashlib
import json
import os
import sys
import time
from datetime import datetime,timezone
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'src'),str(ROOT/'scripts')]
import prepare_inspector_recovery001_live as preview
import sign_inspector_recovery001_allowance as signing
import prepare_inspector_recovery001_shutdown as shutdown
from factory_runtime.inspector_recovery001 import TABLE,PK,SCOPE_SHA256
from factory_runtime.pilot002_attempts import TABLE as OLD_TABLE,key
from factory_runtime.inspector_recovery001_authorization import verify
from factory_state.scope import canonical
from factory_state.signers import validate_trusted_signers
from factory_state.model import StateError

NAME=preview.disabled.FUNCTION


def require(condition,message):
    if not condition:raise StateError(message)


def run(plan,proof,envelope,*,approved_plan_digest,approved_preview_digest,signing_workflow_run,
        output,session,clock=lambda:datetime.now(timezone.utc),sleep=time.sleep):
    output=Path(output)
    require(output.is_dir(),'Output directory required')
    require(type(signing_workflow_run) is int and signing_workflow_run>0,'Signing run required')
    require(signing.digest(proof)==approved_preview_digest,'Exact preview approval required')
    require(proof['plan_digest']==approved_plan_digest and proof['stack_id']==preview.STACK and
        proof['shared_capacity_approved'] is True and proof['status']=='PREPARED_VALIDATED_NOT_EXECUTED','Preview binding differs')
    require(proof['change_set_arn'].startswith('arn:aws:cloudformation:ca-central-1:666730517561:changeSet/inspector-recovery001-live-'),'Recovery change set required')
    require(proof['rollback_template']==preview.baseline(),'Rollback target differs')
    require(not (output/'recovery-execution-marker.json').exists(),'Execution already started; do not retry')
    def signature():
        now=clock();payload=signing.validate_plan(plan,root=ROOT,approved_digest=approved_plan_digest,now=now)
        require(envelope['payload']==payload,'Signed payload differs')
        bound=signing.context(plan['activation'])
        return verify(envelope,root=ROOT,**bound,request_bytes=signing.request_bytes(ROOT,role='inspector',
            builder_response=bound['builder_response'],candidate_commit=bound['candidate_commit']),
            pricing=plan['pricing'],readiness=plan['activation']['readiness'],
            trusted_keys=validate_trusted_signers(plan['activation']['signer_registry'],now=now),now=now)
    signature()
    from botocore.config import Config
    config=Config(retries={'total_max_attempts':1},connect_timeout=5,read_timeout=210)
    cf=session.client('cloudformation',config=config);lam=session.client('lambda',config=config)
    db=session.client('dynamodb',config=config);iam=session.client('iam',config=config)
    require(session.client('sts',config=config).get_caller_identity()['Account']=='666730517561','Wrong AWS account')
    def template(**kw):
        raw=cf.get_template(**kw)['TemplateBody'];return json.loads(raw) if isinstance(raw,str) else raw
    def original_rows():return {r:db.get_item(TableName=OLD_TABLE,Key=key(r),ConsistentRead=True).get('Item') for r in ('builder','inspector','qa')}
    def recovery_row():return db.get_item(TableName=TABLE,Key={'PK':{'S':PK}},ConsistentRead=True).get('Item')
    baseline=json.loads((ROOT/'factory/evidence/inspector-recovery-001-disabled-deployed.json').read_bytes())
    def workers():
        for r,expected in baseline['workers'].items():
            f=lam.get_function_configuration(FunctionName='tims-factory-pilot-002-'+r)
            require(f['CodeSha256']==expected['code_sha256'] and f['Environment']['Variables']['FACTORY_PILOT002_EXECUTION_ENABLED']=='false' and
                lam.get_function_concurrency(FunctionName=f['FunctionName']).get('ReservedConcurrentExecutions')==0,'Original worker changed')
    def runtime(active):
        target=proof['template'] if active else proof['rollback_template']
        f=lam.get_function_configuration(FunctionName=NAME);expected=target['Resources']['RecoveryFunction']['Properties']
        for field in ('Environment','Handler','Timeout','MemorySize','Runtime','Architectures'):
            require(f[field]==expected[field],'Recovery function configuration differs')
        require(f['Role']==baseline['role_arn'] and f['State']=='Active' and f['LastUpdateStatus']=='Successful','Recovery function not ready')
        require(f['CodeSha256']==(proof['package'] if active else baseline['package'])['code_sha256'],'Recovery code differs')
        concurrency=lam.get_function_concurrency(FunctionName=NAME)
        require(('ReservedConcurrentExecutions' not in concurrency) if active else concurrency.get('ReservedConcurrentExecutions')==0,'Recovery concurrency differs')
        role=preview.disabled.ROLE;properties=target['Resources']['RecoveryRole']['Properties']
        require(iam.get_role(RoleName=role)['Role']['AssumeRolePolicyDocument']==properties['AssumeRolePolicyDocument'],'Role trust differs')
        attached=iam.list_attached_role_policies(RoleName=role)
        require(not attached['AttachedPolicies'] and not attached.get('IsTruncated'),'Unexpected managed permissions')
        policies={v['PolicyName']:v['PolicyDocument'] for v in properties['Policies']}
        if active:
            access=target['Resources']['RecoveryAccess']['Properties'];policies[access['PolicyName']]=access['PolicyDocument']
        names=iam.list_role_policies(RoleName=role)
        require(set(names['PolicyNames'])==set(policies) and not names.get('IsTruncated'),'Unexpected inline permissions')
        for name,expected in policies.items():require(iam.get_role_policy(RoleName=role,PolicyName=name)['PolicyDocument']==expected,'Recovery permissions differ')
    require(template(StackName=preview.STACK)==proof['rollback_template'],'Disabled stack drift')
    changes=cf.describe_change_set(ChangeSetName=proof['change_set_arn'])
    target=template(ChangeSetName=proof['change_set_arn'])
    require(target==proof['template'],'Preview template changed')
    preview.validate(target,changes,proof['package'],proof['code'],activation=canonical(plan['activation']),now=clock(),shared_capacity_approved=True)
    runtime(False);workers();rows=original_rows()
    require(rows['builder']['status']['S']=='COMPLETE' and rows['inspector']['status']['S']=='STARTED' and rows['qa'] is None and
        rows['inspector']['reservation_status']['S']=='HELD' and rows['inspector']['reserved_micro_usd']['N']=='250000','Original attempt state changed')
    require(not recovery_row(),'Recovery attempt already consumed')
    artifact=session.client('s3',config=config).get_object(Bucket=proof['code']['S3Bucket'],Key=proof['code']['S3Key'],VersionId=proof['code']['S3ObjectVersion'])
    raw=artifact['Body'].read(5000001)
    require(artifact['VersionId']==proof['code']['S3ObjectVersion'] and len(raw)==proof['package']['zip_bytes'] and hashlib.sha256(raw).hexdigest()==proof['package']['sha256'],'Artifact differs')
    require(lam.get_account_settings()['AccountLimit']['UnreservedConcurrentExecutions']>=1,'No shared capacity')
    for operation,field in (('list_event_source_mappings','EventSourceMappings'),('list_aliases','Aliases'),('list_function_url_configs','FunctionUrlConfigs')):
        result=getattr(lam,operation)(FunctionName=NAME);require(not result[field] and not result.get('NextMarker'),'Unexpected invocation surface')
    try:lam.get_policy(FunctionName=NAME)
    except lam.exceptions.ResourceNotFoundException:pass
    else:raise StateError('Unexpected invocation permission')
    rules=session.client('events',config=config).list_rule_names_by_target(TargetArn=baseline['function_arn'])
    require(not rules['RuleNames'] and not rules.get('NextToken'),'Unexpected event rule')
    scheduler=session.client('scheduler',config=config)
    def shutdown_armed():
        require(proof['shutdown_deadline']<=envelope['payload']['expires_at'],'Shutdown exceeds signed window')
        shutdown.validate_armed(scheduler.get_schedule(Name=shutdown.NAME,GroupName=shutdown.GROUP),
            proof['shutdown_deadline'],now=clock())
    shutdown_armed()
    for page in scheduler.get_paginator('list_schedules').paginate():
        for entry in page.get('Schedules',[]):
            if entry['Name']==shutdown.NAME and entry['GroupName']==shutdown.GROUP:continue
            target=scheduler.get_schedule(Name=entry['Name'],GroupName=entry['GroupName'])['Target']
            require(NAME not in target['Arn'] and NAME not in target.get('Input',''),'Unexpected schedule')
    report={'status':'EXECUTION_STARTED','plan_digest':approved_plan_digest,'preview_digest':approved_preview_digest,
        'signing_workflow_run':signing_workflow_run,'lambda_requests':0,'shutdown_verified':False}
    def save(): (output/'recovery-report.json').write_text(json.dumps(report,indent=2)+'\n')
    with (output/'recovery-execution-marker.json').open('x') as marker:
        json.dump(report,marker);marker.flush();os.fsync(marker.fileno())
    token=approved_preview_digest.removeprefix('sha256:')
    try:
        save()
        cf.execute_change_set(ChangeSetName=proof['change_set_arn'],ClientRequestToken='recovery001-'+token)
        cf.get_waiter('stack_update_complete').wait(StackName=preview.STACK,WaiterConfig={'Delay':3,'MaxAttempts':60})
        require(template(StackName=preview.STACK)==proof['template'],'Active stack differs');runtime(True);workers();signature();shutdown_armed()
        require(not recovery_row() and original_rows()==rows,'Attempt state changed before invocation')
        event=canonical({'kind':'inspector_recovery001_run_once','allowance':envelope})
        with (output/'recovery-invocation-marker.json').open('x') as marker:
            json.dump({'event_sha256':hashlib.sha256(event).hexdigest(),'no_retry':True},marker);marker.flush();os.fsync(marker.fileno())
        report.update(lambda_requests=1,status='INVOCATION_SUBMITTED_NO_RETRY');save()
        response=lam.invoke(FunctionName=NAME,InvocationType='RequestResponse',LogType='None',Payload=event)
        raw=response['Payload'].read(524289);require(len(raw)<=524288,'Result exceeds bound')
        (output/'recovery-result.json').write_bytes(raw)
        report.update(response_sha256=hashlib.sha256(raw).hexdigest(),response_bytes=len(raw))
        require(response.get('StatusCode')==200 and not response.get('FunctionError'),'Recovery invocation failed')
        result=json.loads(raw)
        require(result.get('role')=='inspector' and result.get('recovery_scope_digest')=='sha256:'+SCOPE_SHA256 and
            result.get('gate_authority') is False and result.get('production_release_authorized') is False,'Recovery result scope differs')
        require(result.get('status') in ('INSPECTOR_RECOVERY001_COMPLETED_UNSIGNED','INSPECTOR_RECOVERY001_FAILED_NO_RETRY'),'Unknown recovery result')
        report.update(status='RESPONSE_STORED_UNTRUSTED_NO_RETRY' if result['status']=='INSPECTOR_RECOVERY001_COMPLETED_UNSIGNED' else 'STOPPED_NO_RETRY',result_status=result['status'])
    except Exception as error:report.update(status='STOPPED_NO_RETRY',error_type=type(error).__name__)
    finally:
        errors=[]
        def attempt(stage,operation):
            try:operation()
            except Exception as error:errors.append(stage+':'+type(error).__name__)
        off=lambda:lam.put_function_concurrency(FunctionName=NAME,ReservedConcurrentExecutions=0)
        attempt('immediate_off',off)
        def settle():
            for _ in range(90):
                if not cf.describe_stacks(StackName=preview.STACK)['Stacks'][0]['StackStatus'].endswith('_IN_PROGRESS'):return
                sleep(2)
            raise StateError('Stack did not settle')
        attempt('settle',settle);attempt('final_off',off)
        def rollback():
            if template(StackName=preview.STACK)!=proof['rollback_template']:
                cf.update_stack(StackName=preview.STACK,TemplateBody=json.dumps(proof['rollback_template']),Capabilities=['CAPABILITY_NAMED_IAM'],ClientRequestToken='recovery001-off-'+token)
                cf.get_waiter('stack_update_complete').wait(StackName=preview.STACK,WaiterConfig={'Delay':3,'MaxAttempts':60})
            require(template(StackName=preview.STACK)==proof['rollback_template'],'Rollback template differs')
            require(cf.describe_stacks(StackName=preview.STACK)['Stacks'][0]['StackStatus'] in
                ('CREATE_COMPLETE','UPDATE_COMPLETE','UPDATE_ROLLBACK_COMPLETE'),'Rollback stack not settled')
            runtime(False);workers();require(original_rows()==rows,'Original attempt records changed')
            report['shutdown_verified']=True
        attempt('rollback',rollback)
        attempt('reconciliation',lambda:report.update(recovery_attempt=recovery_row()))
        report.update(shutdown_errors=errors,finished_at=clock().isoformat());save()
    return report


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('allowance',type=Path);parser.add_argument('output',type=Path)
    parser.add_argument('--approved-plan-digest',required=True);parser.add_argument('--approved-preview-digest',required=True)
    parser.add_argument('--signing-workflow-run',required=True,type=int);args=parser.parse_args()
    import boto3
    result=run(signing.read_plan(ROOT/'factory/evidence/inspector-recovery-001-signing-candidate.json'),
        signing.read_plan(ROOT/'factory/evidence/inspector-recovery-001-live-preview.json'),signing.read_plan(args.allowance),
        approved_plan_digest=args.approved_plan_digest,approved_preview_digest=args.approved_preview_digest,
        signing_workflow_run=args.signing_workflow_run,output=args.output,session=boto3.Session(region_name='ca-central-1'))
    print(json.dumps({k:v for k,v in result.items() if k!='recovery_attempt'},indent=2))
    sys.exit(0 if result['shutdown_verified'] and result['status']=='RESPONSE_STORED_UNTRUSTED_NO_RETRY' else 1)
