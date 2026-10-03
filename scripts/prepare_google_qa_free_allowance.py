"""Prepare an UNSIGNED zero-dollar proposal after a fresh operator billing check."""
import argparse
import hashlib
import json
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'src'))
from factory_runtime.google_qa import MODEL, ENDPOINT, request_body
from factory_runtime.google_qa_boundary import ACTIVATION
from factory_runtime.google_qa_broker_runtime import configuration
from factory_runtime.google_qa_authorization import digest
from factory_runtime.review_preparation import prepare
from factory_state.model import OWNER_IDENTITY, StateError


def proposal(root, *, source_commit, billing, now):
    pricing,_=configuration(root,now)
    if (pricing.get('kind')!='google_qa_free_tier_policy' or
            pricing.get('billing_mode')!='UNLINKED_FREE_TIER' or
            not pricing['issued_at']<=now.timestamp()<pricing['expires_at'] or
            not isinstance(source_commit,str) or not re.fullmatch('[0-9a-f]{40}',source_commit) or
            not isinstance(billing,dict) or set(billing)!={'google_project','billing_account_linked','observed_at','evidence_digest'} or
            billing['google_project']!='gen-lang-client-0247455615' or billing['billing_account_linked'] is not False or
            type(billing['observed_at']) is not int or not billing['observed_at']<=now.timestamp()<billing['observed_at']+300 or
            not isinstance(billing['evidence_digest'],str) or not re.fullmatch('sha256:[0-9a-f]{64}',billing['evidence_digest'])):
        raise StateError('free-tier proposal requires current unlinked billing evidence and policy')
    packet=prepare(root,role='qa')
    return {'kind':'google_qa_allowance','owner_identity':OWNER_IDENTITY,
        'activation_id':ACTIVATION,'source_commit':source_commit,'model_id':MODEL,'endpoint':ENDPOINT,
        **{k:packet[k] for k in ('candidate_commit','contract_digest','packet_digest')},
        'request_digest':'sha256:'+hashlib.sha256(request_body(packet,root=root)).hexdigest(),
        'pricing_digest':digest(pricing),'reserved_micro_usd':0,'approved_cap_micro_usd':0,
        'maximum_provider_calls':1,'retries':0,'task_state_writes':0,'gate_authority':False,
        'production_release_authorized':False,'billing_evidence':dict(billing),
        'issued_at':int(now.timestamp()),'expires_at':min(billing['observed_at']+300,pricing['expires_at'])}


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('billing_evidence',type=Path); parser.add_argument('output',type=Path)
    args=parser.parse_args()
    if subprocess.check_output(['git','status','--porcelain'],cwd=ROOT,text=True).strip():
        raise RuntimeError('allowance preparation requires clean reviewed source')
    commit=subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip()
    payload=proposal(ROOT,source_commit=commit,billing=json.loads(args.billing_evidence.read_bytes()),now=datetime.now(timezone.utc))
    with args.output.open('x',encoding='utf-8') as stream: json.dump(payload,stream,indent=2)
    print(json.dumps({'status':'UNSIGNED_NOT_AUTHORIZED','payload_digest':digest(payload),
        'maximum_cost_usd':'0.00','maximum_provider_calls':1,'retries':0,'expires_at':payload['expires_at']}))
