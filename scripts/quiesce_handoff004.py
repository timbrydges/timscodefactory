"""Repeatable interrupted-session shutdown; no invocation or ledger writes."""
import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'src'),str(ROOT/'scripts')]
from prepare_handoff004_dispatcher import NAME,policy,ACCOUNT,REGION
from factory_runtime.handoff004_attempts import ROLES
from factory_state.model import StateError

FUNCTIONS=(NAME,)+tuple('tims-factory-handoff-004-'+r for r in ROLES)


def quiesce(*,sts,lam,iam,record):
    """Try every stop independently; failed reads never prove shutdown.

    Zero concurrency blocks new invocations, but does not cancel in-flight work.
    Code and all durable attempt/hold records remain untouched.
    """
    for client in (sts,lam,iam):
        if client.meta.config.retries.get('total_max_attempts')!=1:
            raise StateError('Shutdown requires no automatic SDK retries')
    if lam.meta.region_name!=REGION:
        raise StateError('Fixed Factory Lambda region required')
    if sts.get_caller_identity().get('Account')!=ACCOUNT:
        raise StateError('Fixed Factory account required')
    errors=[]
    def step(name,operation):
        # Failure to journal must never prevent a later independent stop.
        try:record({'stage':'STOP_STARTED','target':name})
        except Exception:errors.append('journal:'+name)
        try:operation()
        except Exception:errors.append(name)
    for name in FUNCTIONS:
        step(name,lambda name=name:lam.put_function_concurrency(
            FunctionName=name,ReservedConcurrentExecutions=0))
    def narrow_policy():
        current=iam.get_role_policy(RoleName=NAME,PolicyName='exact-dispatch')['PolicyDocument']
        versions={}
        for entry in current.get('Statement',[]):
            if entry.get('Action')==['lambda:GetFunctionConfiguration','lambda:InvokeFunction']:
                for arn in entry.get('Resource',[]):
                    for role in ROLES:
                        prefix=f'arn:aws:lambda:{REGION}:{ACCOUNT}:function:tims-factory-handoff-004-{role}:'
                        if isinstance(arn,str) and arn.startswith(prefix):
                            if role in versions:raise StateError('Duplicate worker binding')
                            versions[role]=arn
        if current!=policy(versions):raise StateError('Unexpected dispatcher policy; no policy replacement')
        if versions:
            iam.put_role_policy(RoleName=NAME,PolicyName='exact-dispatch',PolicyDocument=json.dumps(policy({})))
    step('dispatcher-invoke-policy',narrow_policy)
    observations={}
    for name in FUNCTIONS:
        try:
            value=lam.get_function_concurrency(FunctionName=name)
            disabled=type(value.get('ReservedConcurrentExecutions')) is int and value['ReservedConcurrentExecutions']==0
        except Exception:disabled=False
        observations[name]={'zero_concurrency_observed':disabled}
        if not disabled:errors.append('verify:'+name)
    try:no_invoke=iam.get_role_policy(RoleName=NAME,PolicyName='exact-dispatch')['PolicyDocument']==policy({})
    except Exception:no_invoke=False
    if not no_invoke:errors.append('verify:dispatcher-invoke-policy')
    result={'status':'QUIESCED_NEW_INVOCATIONS_BLOCKED' if not errors else 'SHUTDOWN_INCOMPLETE',
        'observed_at':datetime.now(timezone.utc).isoformat(),'functions':observations,
        'dispatcher_invoke_permissions_removed':no_invoke,'errors':sorted(set(errors)),
        'model_calls':0,'ledger_writes':0,'code_changes':0,'running_invocations_cancelled':False,
        'execution_authorized':False,'limitation':'Already-running work may finish; reconcile durable claims before any later activation.'}
    try:record({'stage':'STOP_FINISHED','result':result})
    except Exception:
        result['errors'].append('journal:finish');result['status']='SHUTDOWN_INCOMPLETE'
    return result


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('output',type=Path)
    args=parser.parse_args()
    import boto3
    from botocore.config import Config
    config=Config(retries={'total_max_attempts':1},connect_timeout=5,read_timeout=10)
    session=boto3.Session(region_name=REGION)
    # Exclusive output is opened before making any cloud change.
    with args.output.open('x',encoding='utf-8') as journal:
        def record(value):
            journal.write(json.dumps(value,sort_keys=True)+'\n');journal.flush();os.fsync(journal.fileno())
        result=quiesce(sts=session.client('sts',config=config),lam=session.client('lambda',config=config),
            iam=session.client('iam',config=config),record=record)
    print(json.dumps(result,sort_keys=True))
    return 0 if result['status']=='QUIESCED_NEW_INVOCATIONS_BLOCKED' else 2


if __name__=='__main__':raise SystemExit(main())
