"""Sign one exact current-stage scope in the owner or independent reviewer job."""
import argparse
import base64
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import subprocess
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'src'));sys.path.insert(0,str(ROOT))
from scripts.sign_bounded_review_allowance import decode
from scripts.prepare_bounded_review_material import prepare
from factory_runtime.intake import IntakePlan
from factory_runtime.review_material import PinnedReviewMaterial
from factory_runtime.review_scope_signing import check_plan, ReviewCapabilitySigner, independent_signer
from factory_runtime.worker import digest
from factory_state.dispatch import DispatchRequest
from factory_state.dynamodb import DynamoDBStateStore
from factory_state.model import Lease, StateError
from factory_state.scope import canonical
from factory_state.signers import load_trusted_signers


def context(packet, *, approved_digest, source_commit, mode, root=ROOT, clock, importer=prepare):
    fields={'kind','source_commit','role','proof_run_id','material_digest','plan','owner_signature_base64'}
    if (mode not in ('owner','spec') or type(packet)is not dict or set(packet)!=fields or
            digest(canonical(packet))!=approved_digest or packet['kind']!='bounded_review001_scope_signing_plan' or
            packet['source_commit']!=source_commit or type(packet['proof_run_id'])is not int or packet['proof_run_id']<=0):
        raise StateError('exact reviewed scope packet required')
    try:
        p=packet['plan']
        if type(p)is not dict or set(p)!=set(IntakePlan.__dataclass_fields__):raise ValueError('plan fields')
        lease=Lease(**{**p['lease'],'expires_at':datetime.fromisoformat(p['lease']['expires_at'])})
        plan=IntakePlan(**{**p,'lease':lease,'request':DispatchRequest(**p['request'])})
        signature=base64.b64decode(packet['owner_signature_base64'],validate=True)
        if (mode=='owner' and signature) or (mode=='spec' and len(signature)!=64):raise ValueError('signature')
    except (ValueError,TypeError,KeyError):raise StateError('scope packet fields invalid') from None
    raw=importer(source_commit,packet['proof_run_id'],root=root,clock=clock)
    material=PinnedReviewMaterial.load(raw,expected_digest=packet['material_digest'],deployed_commit=source_commit,clock=clock)
    check_plan(material,packet['role'],plan,clock())
    return material,plan,signature


def sign_packet(packet, *, approved_digest, source_commit, mode, kms, sts, states, root=ROOT, clock, importer=prepare):
    material,plan,signature=context(packet,approved_digest=approved_digest,source_commit=source_commit,
        mode=mode,root=root,clock=clock,importer=importer)
    keys=lambda now:load_trusted_signers(root/'factory/profiles/scope-signers.json',now=now)
    if mode=='owner':
        signer=ReviewCapabilitySigner(material=material,role=packet['role'],plan=plan,kms=kms,sts=sts,
            key_loader=keys,clock=clock,enabled=True)
        payload=plan.capability_payload
    else:
        signer=independent_signer(material=material,role=packet['role'],plan=plan,owner_signature=signature,
            states=states,key_loader=keys,clock=clock,kms=kms,sts=sts,enabled=True)
        payload=plan.review_payload
    return {'payload':payload,'signature_base64':base64.b64encode(signer.sign(payload,now=clock())).decode()}


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('output',type=Path);parser.add_argument('--mode',choices=['owner','spec'],required=True)
    parser.add_argument('--approved-plan-digest',required=True);args=parser.parse_args()
    source=subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip()
    if (source!=os.environ.get('GITHUB_SHA') or os.environ.get('GITHUB_RUN_ATTEMPT')!='1' or
            os.environ.get('GITHUB_REF')!='refs/heads/main' or os.environ.get('GITHUB_ACTOR_ID')!='214414801'):
        raise StateError('first-attempt reviewed main workflow required')
    packet=decode(os.environ.get('BOUNDED_SCOPE_PLAN_BASE64',''))
    import boto3
    from botocore.config import Config
    config=Config(retries={'total_max_attempts':1},connect_timeout=5,read_timeout=30)
    session=boto3.Session(region_name='ca-central-1')
    states=DynamoDBStateStore('tims-software-factory-state',session.client('dynamodb',config=config)) if args.mode=='spec' else None
    with args.output.open('x',encoding='utf-8') as output:
        output.write('{"status":"SIGNING_STARTED_NO_RETRY"}\n');output.flush();os.fsync(output.fileno())
        result=sign_packet(packet,approved_digest=args.approved_plan_digest,source_commit=source,mode=args.mode,
            kms=session.client('kms',config=config),sts=session.client('sts',config=config),states=states,
            clock=lambda:datetime.now(timezone.utc))
        output.seek(0);output.write(json.dumps(result));output.truncate();output.flush();os.fsync(output.fileno())
    print('SCOPE_SIGNED_NO_DEPLOYMENT_OR_MODEL_CALLS')
