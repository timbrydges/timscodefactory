"""Write a reviewable offline QA gate proposal; never approve, sign or write state."""
import argparse
import json
import subprocess
import sys
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'src'))
from factory_runtime.qa_gate import AUTHORIZATION,BASELINE_SHA,LEASE_ID,baseline,evidence


def propose(root, commit):
    facts=evidence(root); state=baseline(root)
    return {'status':'PROPOSED_NOT_AUTHORIZED','authorization_id':AUTHORIZATION,
        'reviewed_source_commit':commit,'factory_id':state.factory_id,'task_id':state.task_id,
        'baseline_sha256':BASELINE_SHA,'from_state':'QA','from_version':12,
        'lease_id':LEASE_ID,'lease_version':13,'target_state':'SECURITY_REVIEW','target_version':14,
        'maximum_lease_seconds':3600,'maximum_signing_invocations':1,'signing_retries':0,
        'model_calls':0,'new_iam_permissions':0,'new_keys':0,'schedule_enabled':False,
        'security_execution_authorized':False,'production_release_authorized':False,
        'evidence':facts,'required_owner_decision':
            'Accept the pinned recorded unsigned Google assessment with verified signed tests; '
            'authorize one fresh QA lease, one QA gate signature and controller advancement to Security Review.',
        'requires':['Unchanged live QA version 12 and active enrolled QA key',
            'Explicit owner approval before enabling either entrypoint',
            'Exact reviewed package and matching bounded deployment configuration',
            'Durable exclusive signing invocation journal and shutdown after the attempt']}


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('output',type=Path)
    args=parser.parse_args()
    commit=subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip()
    if subprocess.check_output(['git','status','--porcelain'],cwd=ROOT,text=True).strip():
        raise SystemExit('QA gate proposal requires clean reviewed source')
    with args.output.open('x',encoding='utf-8') as output:
        json.dump(propose(ROOT,commit),output,indent=2); output.write('\n')
    print('PROPOSED_NOT_AUTHORIZED: no signing, provider call or state change')
