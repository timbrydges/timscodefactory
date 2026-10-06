"""Read current handoff002 attempts and compute a no-dispatch controller decision."""
import argparse
from datetime import datetime,timezone
import json
from pathlib import Path
import sys
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'src'),str(ROOT/'scripts')]
from factory_runtime.handoff002_attempts import TABLE,ROLES,key
from factory_runtime.handoff002_controller import decide
from factory_state.signers import validate_trusted_signers
from verify_handoff002_saved_evidence import verify,SOURCE,CANDIDATE


def observe(sts,db,now):
    if sts.get_caller_identity().get('Account')!='666730517561':raise ValueError('Wrong account')
    folder=ROOT/'factory/evidence/handoff-002-live'
    verify(folder)  # Independently check the saved candidate/test observation.
    saved=json.loads((folder/'chain-verification.json').read_bytes())
    envelopes={r:json.loads((folder/(r+'-live-result.json')).read_bytes()) for r in ROLES}
    # Read failure raises; it can never be substituted for an absent row.
    attempts={r:db.get_item(TableName=TABLE,Key=key(r),ConsistentRead=True).get('Item') for r in ROLES}
    keys=validate_trusted_signers(json.loads((ROOT/'factory/profiles/scope-signers.json').read_bytes()),now=now)
    decision=decide(attempts=attempts,envelopes=envelopes,root=ROOT,trusted_keys=keys,
        source_commit=SOURCE,candidate_commit=CANDIDATE,request_digests=saved['request_digests'],now=now,
        verify_executed_tests=lambda commit,digest:commit==CANDIDATE and digest==saved['candidate_digest'])
    return {**decision,'observed_at':now.isoformat(),'task_id':'authenticated-handoff-002',
        'non_atomic_snapshot':True,'authoritative_task_state_written':False,'model_calls':0}

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('output',type=Path);args=parser.parse_args()
    if args.output.exists():raise ValueError('Use a new observation path')
    import boto3
    from botocore.config import Config
    session=boto3.Session(region_name='ca-central-1');cfg=Config(retries={'total_max_attempts':1})
    result=observe(session.client('sts',config=cfg),session.client('dynamodb',config=cfg),datetime.now(timezone.utc))
    with args.output.open('x') as f:json.dump(result,f,indent=2)
    print(result['status']+'; no dispatch or state write')
