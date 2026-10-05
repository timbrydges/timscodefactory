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
import prepare_qa_recovery002_live as preview
import sign_qa_recovery002_allowance as signing
import prepare_qa_recovery002_shutdown as shutdown
from factory_runtime.qa_recovery002 import TABLE,PK,SCOPE_SHA256
from factory_runtime.qa_recovery001 import TABLE as PREVIOUS_QA_TABLE,PK as PREVIOUS_QA_PK
from factory_runtime.pilot002_attempts import TABLE as OLD_TABLE,key
from factory_runtime.qa_recovery002_authorization import verify,REQUEST_DIGEST
from factory_runtime.inspector_recovery001 import TABLE as INSPECTOR_TABLE,PK as INSPECTOR_PK
from factory_state.scope import canonical
from factory_state.signers import validate_trusted_signers
from factory_state.model import StateError

NAME=preview.disabled.FUNCTION


def require(condition,message):
    if not condition:raise StateError(message)


def run(plan,proof,envelope,*,approved_plan_digest,approved_preview_digest,signing_workflow_run,
        output,session,clock=lambda:datetime.now(timezone.utc),sleep=time.sleep,shutdown_deadline=None):
    output=Path(output)
    require(output.is_dir(),'Output directory required')
    require(type(signing_workflow_run) is int and signing_workflow_run>0,'Signing run required')
    require(signing.digest(proof)==approved_preview_digest,'Exact preview approval required')
    if shutdown_deadline is None:shutdown_deadline=proof.get('shutdown_deadline')
    require(type(shutdown_deadline) is int,'Runtime shutdown deadline required')
    require(proof.get('shutdown_deadline',shutdown_deadline)==shutdown_deadline,'Shutdown deadline differs')
    require(proof['plan_digest']==approved_plan_digest and proof['stack_id']==preview.STACK and
        proof['shared_capacity_approved'] is True and proof['status']=='PREPARED_VALIDATED_NOT_EXECUTED','Preview binding differs')
    require(proof['change_set_arn'].startswith('arn:aws:cloudformation:ca-central-1:666730517561:changeSet/qa-recovery002-live-'),'Recovery change set required')
    require(proof['rollback_template']==preview.baseline(),'Rollback target differs')
    require(not (output/'recovery-execution-marker.json').exists(),'Execution already started; do not retry')
    def signature():
        now=clock();payload=signing.validate_plan(plan,root=ROOT,approved_digest=approved_plan_digest,now=now)
        require(envelope['payload']==payload,'Signed payload differs')
        bound=signing.context(plan['activation'])
        return verify(envelope,root=ROOT,**bound,request_bytes=signing.request_bytes(ROOT,role='qa',
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
    def original_rows():
        rows={r:db.get_item(TableName=OLD_TABLE,Key=key(r),ConsistentRead=True).get('Item') for r in ('builder','inspector','qa')}
        rows['inspector_recovery']=db.get_item(TableName=INSPECTOR_TABLE,Key={'PK':{'S':INSPECTOR_PK}},ConsistentRead=True).get('Item')
        rows['qa_recovery001']=db.get_item(TableName=PREVIOUS_QA_TABLE,Key={'PK':{'S':PREVIOUS_QA_PK}},ConsistentRead=True).get('Item')
        return rows
    def recovery_row():return db.get_item(TableName=TABLE,Key={'PK':{'S':PK}},ConsistentRead=True).get('Item')
    baseline=preview.baseline_proof()
    original=json.loads((ROOT/'factory/evidence/inspector-recovery-001-disabled-deployed.json').read_bytes())
    def workers():
        previous_qa=json.loads((ROOT/'factory/evidence/qa-recovery-001-disabled-deployed.json').read_bytes())
        f=lam.get_function_configuration(FunctionName=previous_qa['function'])
        require(f['CodeSha256']==previous_qa['code_sha256'] and
            f['Environment']['Variables']=={'FACTORY_QA_RECOVERY001_ENABLED':'false'} and
            lam.get_function_concurrency(FunctionName=previous_qa['function']).get('ReservedConcurrentExecutions')==0,'Previous QA recovery worker changed')
        for r,expected in original['workers'].items():
            f=lam.get_function_configuration(FunctionName='tims-factory-pilot-002-'+r)
            require(f['CodeSha256']==expected['code_sha256'] and f['Environment']['Variables']['FACTORY_PILOT002_EXECUTION_ENABLED']=='false' and
                lam.get_function_concurrency(FunctionName=f['FunctionName']).get('ReservedConcurrentExecutions')==0,'Original worker changed')
        f=lam.get_function_configuration(FunctionName='tims-factory-inspector-recovery-001')
        require(f['CodeSha256']==original['package']['code_sha256'] and
            f['Environment']['Variables']=={'FACTORY_INSPECTOR_RECOVERY001_ENABLED':'false'} and
            lam.get_function_concurrency(FunctionName=f['FunctionName']).get('ReservedConcurrentExecutions')==0,'Inspector recovery worker changed')
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
    require(rows['builder']['status']['S']=='COMPLETE' and rows['inspector']['status']['S']=='STARTED' and isinstance(rows['qa'],dict) and rows['qa'].get('status',{}).get('S')=='STARTED' and
        rows['inspector']['reservation_status']['S']=='HELD' and rows['inspector']['reserved_micro_usd']['N']=='250000','Original attempt state changed')
    for role in ('qa','inspector_recovery','qa_recovery001'):
        require(isinstance(rows[role],dict) and rows[role].get('status',{}).get('S')=='STARTED' and
            rows[role].get('reservation_status',{}).get('S')=='HELD' and rows[role].get('reserved_micro_usd',{}).get('N')=='250000','Consumed attempt hold changed')
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
        require(shutdown_deadline<=envelope['payload']['expires_at'],'Shutdown exceeds signed window')
        stamp=clock()
        properties=shutdown.render(int(stamp.timestamp())+1200,now=stamp)['Resources']['ShutdownRole']['Properties']
        require(iam.get_role(RoleName=shutdown.ROLE)['Role']['AssumeRolePolicyDocument']==properties['AssumeRolePolicyDocument'],'Shutdown trust differs')
        attached=iam.list_attached_role_policies(RoleName=shutdown.ROLE)
        require(not attached['AttachedPolicies'] and not attached.get('IsTruncated'),'Unexpected shutdown managed permissions')
        names=iam.list_role_policies(RoleName=shutdown.ROLE)
        policy=properties['Policies'][0]
        require(names['PolicyNames']==[policy['PolicyName']] and not names.get('IsTruncated'),'Unexpected shutdown inline permissions')
        require(iam.get_role_policy(RoleName=shutdown.ROLE,PolicyName=policy['PolicyName'])['PolicyDocument']==policy['PolicyDocument'],'Shutdown permissions differ')
        shutdown.validate_live_window(scheduler.get_schedule(Name=shutdown.NAME,GroupName=shutdown.GROUP),
            shutdown_deadline,allowance_expires_at=envelope['payload']['expires_at'],now=clock())
    shutdown_armed()
    armed_properties=shutdown.properties(shutdown_deadline,now=clock(),armed=True)
    for page in scheduler.get_paginator('list_schedules').paginate():
        for entry in page.get('Schedules',[]):
            if entry['Name']==shutdown.NAME and entry['GroupName']==shutdown.GROUP:continue
            target=scheduler.get_schedule(Name=entry['Name'],GroupName=entry['GroupName'])['Target']
            require(NAME not in target['Arn'] and NAME not in target.get('Input',''),'Unexpected schedule')
    report={'status':'EXECUTION_STARTED','plan_digest':approved_plan_digest,'preview_digest':approved_preview_digest,
        'signing_workflow_run':signing_workflow_run,'shutdown_deadline':shutdown_deadline,'lambda_requests':0,'shutdown_verified':False}
    def save(): (output/'recovery-report.json').write_text(json.dumps(report,indent=2)+'\n')
    with (output/'recovery-execution-marker.json').open('x') as marker:
        json.dump(report,marker);marker.flush();os.fsync(marker.fileno())
    token=approved_preview_digest.removeprefix('sha256:')
    try:
        save()
        cf.execute_change_set(ChangeSetName=proof['change_set_arn'],ClientRequestToken='recovery002-'+token)
        cf.get_waiter('stack_update_complete').wait(StackName=preview.STACK,WaiterConfig={'Delay':3,'MaxAttempts':60})
        require(template(StackName=preview.STACK)==proof['template'],'Active stack differs');runtime(True);workers();signature();shutdown_armed()
        require(not recovery_row() and original_rows()==rows,'Attempt state changed before invocation')
        event=canonical({'kind':'qa_recovery002_run_once','allowance':envelope})
        with (output/'recovery-invocation-marker.json').open('x') as marker:
            json.dump({'event_sha256':hashlib.sha256(event).hexdigest(),'no_retry':True},marker);marker.flush();os.fsync(marker.fileno())
        report.update(lambda_requests=1,status='INVOCATION_SUBMITTED_NO_RETRY');save()
        response=lam.invoke(FunctionName=NAME,InvocationType='RequestResponse',LogType='None',Payload=event)
        raw=response['Payload'].read(524289);require(len(raw)<=524288,'Result exceeds bound')
        (output/'recovery-result.json').write_bytes(raw)
        report.update(response_sha256=hashlib.sha256(raw).hexdigest(),response_bytes=len(raw))
        require(response.get('StatusCode')==200 and not response.get('FunctionError'),'Recovery invocation failed')
        result=json.loads(raw)
        require(result.get('role')=='qa' and result.get('recovery_scope_digest')=='sha256:'+SCOPE_SHA256 and
            result.get('gate_authority') is False and result.get('production_release_authorized') is False,'Recovery result scope differs')
        require(result.get('status') in ('QA_RECOVERY002_COMPLETED_UNSIGNED','QA_RECOVERY002_FAILED_NO_RETRY'),'Unknown recovery result')
        if result['status']=='QA_RECOVERY002_COMPLETED_UNSIGNED':
            require(type(result.get('actual_micro_usd')) is int and result['actual_micro_usd']==0 and
                type(result.get('transport_invocations')) is int and result['transport_invocations']==1 and
                result.get('request_digest')==REQUEST_DIGEST and result.get('source_commit')==plan['activation']['source_commit'] and
                result.get('approval_digest')==signing.digest(envelope['payload']) and
                result.get('reservation_status')=='HELD','QA completion binding differs')
        else:
            require(result.get('accepted_review') is False and result.get('attempt_reusable') is False and
                result.get('failure_stage') in ('response','completion'),'QA failure binding differs')
        report.update(status='RESPONSE_STORED_UNTRUSTED_NO_RETRY' if result['status']=='QA_RECOVERY002_COMPLETED_UNSIGNED' else 'STOPPED_NO_RETRY',result_status=result['status'])
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
                cf.update_stack(StackName=preview.STACK,TemplateBody=json.dumps(proof['rollback_template']),Capabilities=['CAPABILITY_NAMED_IAM'],ClientRequestToken='recovery002-off-'+token)
                cf.get_waiter('stack_update_complete').wait(StackName=preview.STACK,WaiterConfig={'Delay':3,'MaxAttempts':60})
            require(template(StackName=preview.STACK)==proof['rollback_template'],'Rollback template differs')
            require(cf.describe_stacks(StackName=preview.STACK)['Stacks'][0]['StackStatus'] in
                ('CREATE_COMPLETE','UPDATE_COMPLETE','UPDATE_ROLLBACK_COMPLETE'),'Rollback stack not settled')
            runtime(False);workers();require(original_rows()==rows,'Original attempt records changed')
            report['shutdown_verified']=True
        attempt('rollback',rollback)
        report['schedule_disabled']=False
        if report['shutdown_verified']:
            def disarm():
                expected={**armed_properties,'State':'DISABLED'}
                scheduler.update_schedule(**expected,ClientToken=hashlib.sha256(('qa-recovery002-disarm-'+token).encode()).hexdigest())
                actual=scheduler.get_schedule(Name=shutdown.NAME,GroupName=shutdown.GROUP)
                for field,value in expected.items():
                    observed=actual.get(field)
                    if isinstance(observed,datetime):observed=observed.astimezone(timezone.utc).isoformat()
                    require(observed==value,'Shutdown disarm verification differs')
                report['schedule_disabled']=True
            attempt('schedule_disarm',disarm)
        attempt('reconciliation',lambda:report.update(recovery_attempt=recovery_row()))
        report.update(shutdown_errors=errors,finished_at=clock().isoformat());save()
    return report


def read_plan(path):
    from factory_runtime.pilot002_entrypoint import _pairs
    with Path(path).open('rb') as stream:raw=stream.read(131073)
    if not 0<len(raw)<=131072:raise StateError('Recovery input exceeds bound')
    value=json.loads(raw,object_pairs_hook=_pairs)
    if type(value) is not dict:raise StateError('Recovery input object required')
    return value


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('plan','preview','allowance','output'):parser.add_argument(name,type=Path)
    parser.add_argument('--approved-plan-digest',required=True);parser.add_argument('--approved-preview-digest',required=True)
    parser.add_argument('--signing-workflow-run',required=True,type=int)
    parser.add_argument('--shutdown-deadline',required=True,type=int);args=parser.parse_args()
    import boto3
    result=run(read_plan(args.plan),read_plan(args.preview),read_plan(args.allowance),
        approved_plan_digest=args.approved_plan_digest,approved_preview_digest=args.approved_preview_digest,
        signing_workflow_run=args.signing_workflow_run,shutdown_deadline=args.shutdown_deadline,
        output=args.output,session=boto3.Session(region_name='ca-central-1'))
    print(json.dumps({k:v for k,v in result.items() if k!='recovery_attempt'},indent=2))
    sys.exit(0 if result['shutdown_verified'] and result['schedule_disabled'] and result['status']=='RESPONSE_STORED_UNTRUSTED_NO_RETRY' else 1)
