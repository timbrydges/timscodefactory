"""Offline Builder cost proposal. Never signs, activates or contacts providers."""
import argparse
from datetime import datetime,timezone
import json
from pathlib import Path
import re
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'src'))
from factory_runtime.pilot002_adapter import Pilot002Adapter
from factory_runtime.pilot002_packets import builder_packet,digest
from check_pilot002_builder_tokens import prepare


def propose(root,observation,review,source_commit,now):
    if not re.fullmatch('[0-9a-f]{40}',source_commit):raise ValueError('source commit')
    if now.tzinfo is None:raise ValueError('aware clock required')
    plan=prepare(root)
    expected={'status':'INPUT_TOKEN_COUNT_OBSERVED','http_status':200,'http_requests':1,
        'generation_requests':0,'attempt_claims':0,'cost_qualified':False,'live_execution_authorized':False,
        'generation_request_digest':plan['generation_request_digest'],'count_request_digest':plan['count_request_digest']}
    if any(type(observation.get(k)) is not type(v) or observation[k]!=v for k,v in expected.items()):raise ValueError('token evidence differs')
    if type(observation.get('input_tokens')) is not int or not 0<observation['input_tokens']<=32768:raise ValueError('input bound')
    rates={'status':'REVIEW_CANDIDATE_NOT_LIVE_AUTHORIZATION','model_id':'gpt-5.6-sol','currency':'USD',
        'input_micro_usd_per_million':4000000,'output_micro_usd_per_million':20000000,
        'input_token_bound':32768,'output_token_bound':4096,'maximum_cost_micro_usd':212992,
        'model_generation_access_proven':False,'live_execution_authorized':False}
    if any(type(review.get(k)) is not type(v) or review[k]!=v for k,v in rates.items()):raise ValueError('price review differs')
    stamps=[datetime.fromisoformat(value['observed_at']) for value in (observation,review)]
    if any(stamp.tzinfo is None or not 0<=(now-stamp).total_seconds()<86400 for stamp in stamps):raise ValueError('stale or future evidence')
    expiry=min(int(stamp.timestamp())+86400 for stamp in stamps)
    packet=builder_packet(root)
    qualification={'kind':'pilot002_provider_rate_qualification','role':'builder','model_id':packet['model_id'],
        'task_id':packet['task_id'],'source_commit':source_commit,'contract_digest':packet['contract_digest'],
        'packet_digest':packet['packet_digest'],'request_digest':plan['generation_request_digest'],'currency':'USD',
        'complete_request_bound_qualified':True,'combined_output_bound_qualified':True,
        'standard_text_only_no_cache_rates':True,'input_token_bound':32768,'output_token_bound':4096,
        'input_micro_usd_per_million':4000000,'output_micro_usd_per_million':20000000,
        'issued_at':int(now.timestamp()),'expires_at':expiry,
        'evidence_digest':digest({'token_observation':observation,'price_review':review})}
    adapter=Pilot002Adapter(root,role='builder',source_commit=source_commit,qualification=qualification,clock=lambda:now,enabled=False)
    return {'status':'QUALIFICATION_PROPOSED_AWAITING_REVIEW','qualification':qualification,'pricing':adapter.pricing,
        'reserved_micro_usd':250000,'live_execution_authorized':False,
        'remaining_gates':['verified model access or owner-accepted Builder first-generation readiness','fresh repository and runtime readiness',
            'reviewed owner-only signer configuration','exact owner-signed allowance','approved runtime activation']}


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('source_commit');args=parser.parse_args()
    observation=json.loads((ROOT/'factory/evidence/pilot-002-builder-token-verified.json').read_text())
    review=json.loads((ROOT/'factory/evidence/pilot-002-builder-price-review.json').read_text())
    print(json.dumps(propose(ROOT,observation,review,args.source_commit,datetime.now(timezone.utc)),indent=2))
