"""Write a reviewable offline Security gate proposal; never approve, sign or write state."""
import argparse
import json
import subprocess
import sys
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'src'))
from factory_runtime.security_gate import AUTHORIZATION,BASELINE_SHA,LEASE_ID,baseline,evidence


def propose(root, commit):
    facts=evidence(root); state=baseline(root)
    return {'status':'PROPOSED_NOT_AUTHORIZED','authorization_id':AUTHORIZATION,
        'reviewed_source_commit':commit,'factory_id':state.factory_id,'task_id':state.task_id,
        'baseline_sha256':BASELINE_SHA,'from_state':'SECURITY_REVIEW','from_version':14,
        'lease_id':LEASE_ID,'lease_version':15,'target_state':'RELEASE_READY','target_version':16,
        'maximum_lease_seconds':3600,'maximum_signing_invocations':1,'signing_retries':0,
        'model_calls':0,'new_keys':0,'schedule_enabled':False,
        'temporary_controller_state_access_required':True,
        'temporary_state_actions':['dynamodb:GetItem','dynamodb:PutItem','dynamodb:UpdateItem'],
        'permission_approval_status':'PENDING_BOUNDED_LIVE_APPROVAL',
        'candidate_execution_authorized':False,'production_release_authorized':False,
        'evidence':facts,'required_owner_decision':
            'Use the approved synthetic-only findings disposition; '
            'authorize one fresh Security lease, one Security gate signature and controller advancement to Release Ready without release authority.',
        'requires':['Unchanged live Security Review version 14 and active enrolled Security key',
            'Separate approval for bounded controller task-partition state access',
            'Explicit owner approval before enabling either entrypoint',
            'Exact reviewed package and matching bounded deployment configuration',
            'Durable exclusive signing invocation journal and shutdown after the attempt']}


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('output',type=Path)
    args=parser.parse_args()
    commit=subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip()
    if subprocess.check_output(['git','status','--porcelain'],cwd=ROOT,text=True).strip():
        raise SystemExit('Security gate proposal requires clean reviewed source')
    with args.output.open('x',encoding='utf-8') as output:
        json.dump(propose(ROOT,commit),output,indent=2); output.write('\n')
    print('PROPOSED_NOT_AUTHORIZED: no signing, provider call or state change')
