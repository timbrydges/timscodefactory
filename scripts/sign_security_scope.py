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
from factory_runtime.security_material import PinnedSecurityMaterial
from factory_runtime.review_verdict import ReviewBinding
from factory_runtime.security_qa_provenance import ConsumedQAProvenance
from factory_runtime.security_scope_policy import SecurityScopeReview, SecurityScopeSigner
from factory_runtime.security_capability_signing import check_plan, SecurityCapabilitySigner
from factory_runtime.worker import digest
from factory_state.dispatch import DispatchRequest, DynamoDBDispatchStore
from factory_state.dynamodb import DynamoDBStateStore
from factory_state.model import Lease, StateError
from factory_state.scope import canonical
from factory_state.signers import load_trusted_signers, validate_trusted_signers


def context(packet, *, approved_digest, source_commit, mode, root=ROOT, clock, importer=prepare):
    fields={'kind','source_commit','role','proof_run_id','material_digest','qa_binding','qa_request','qa_result_digest','historical_signers','plan','owner_signature_base64'}
    if (mode not in ('owner','spec') or type(packet)is not dict or set(packet)!=fields or
            digest(canonical(packet))!=approved_digest or packet['kind']!='bounded_security004_scope_signing_plan' or
            packet['source_commit']!=source_commit or packet['role']!='security' or type(packet['proof_run_id'])is not int or packet['proof_run_id']<=0):
        raise StateError('exact reviewed scope packet required')
    try:
        p=packet['plan']
        if type(p)is not dict or set(p)!=set(IntakePlan.__dataclass_fields__):raise ValueError('plan fields')
        lease=Lease(**{**p['lease'],'expires_at':datetime.fromisoformat(p['lease']['expires_at'])})
        plan=IntakePlan(**{**p,'lease':lease,'request':DispatchRequest(**p['request'])})
        signature=base64.b64decode(packet['owner_signature_base64'],validate=True)
        if (mode=='owner' and signature) or (mode=='spec' and len(signature)!=64):raise ValueError('signature')
    except (ValueError,TypeError,KeyError):raise StateError('scope packet fields invalid') from None
    try:
        q=packet['qa_binding']
        if type(q) is not dict or set(q)!=set(ReviewBinding.__dataclass_fields__) or type(q['allowed_paths']) is not list:
            raise ValueError('QA shape')
        qa=ReviewBinding(**{**q,'allowed_paths':tuple(q['allowed_paths'])})
        qa_request=DispatchRequest(**packet['qa_request'])
        history=packet['historical_signers']
        if type(history) is not dict or {e['identity'] for e in history['signers']}!={'qa_engineer_service'}:
            raise ValueError('QA-only historical keys required')
    except (ValueError,TypeError,KeyError):
        raise StateError('Exact historical QA configuration required') from None
    raw=importer(source_commit,packet['proof_run_id'],root=root,clock=clock)
    material=PinnedSecurityMaterial.load(raw,expected_digest=packet['material_digest'],deployed_commit=source_commit,
        qa_binding=qa,qa_result_digest=packet['qa_result_digest'],clock=clock)
    check_plan(material,plan,clock())
    return material,plan,signature,qa,qa_request,history


def sign_packet(packet, *, approved_digest, source_commit, mode, kms, sts, states, ledger, root=ROOT, clock, importer=prepare):
    material,plan,signature,qa,qa_request,history=context(packet,approved_digest=approved_digest,source_commit=source_commit,
        mode=mode,root=root,clock=clock,importer=importer)
    keys=lambda now:load_trusted_signers(root/'factory/profiles/scope-signers.json',now=now)
    if mode=='owner':
        signer=SecurityCapabilitySigner(material=material,plan=plan,kms=kms,sts=sts,
            key_loader=keys,clock=clock,enabled=True)
        payload=plan.capability_payload
    else:
        prerequisite=ConsumedQAProvenance(binding=material.binding,qa_binding=qa,qa_request=qa_request,
            states=states,ledger=ledger,historical_key_loader=lambda now:validate_trusted_signers(history,now=now),
            clock=clock,contract_bytes=material.contract_bytes)
        policy=SecurityScopeReview(material=material,plan=plan,owner_signature=signature,
            prerequisites=prerequisite,key_loader=keys,clock=clock)
        signer=SecurityScopeSigner(policy=policy,kms=kms,sts=sts,enabled=True)
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
    packet=decode(os.environ.get('SECURITY_SCOPE_PLAN_BASE64',''))
    import boto3
    from botocore.config import Config
    config=Config(retries={'total_max_attempts':1},connect_timeout=5,read_timeout=30)
    session=boto3.Session(region_name='ca-central-1')
    states=DynamoDBStateStore('tims-software-factory-state',session.client('dynamodb',config=config)) if args.mode=='spec' else None
    with args.output.open('x',encoding='utf-8') as output:
        output.write('{"status":"SIGNING_STARTED_NO_RETRY"}\n');output.flush();os.fsync(output.fileno())
        result=sign_packet(packet,approved_digest=args.approved_plan_digest,source_commit=source,mode=args.mode,
            kms=session.client('kms',config=config),sts=session.client('sts',config=config),states=states,ledger=DynamoDBDispatchStore('tims-software-factory-state',session.client('dynamodb',config=config)) if args.mode=='spec' else None,
            clock=lambda:datetime.now(timezone.utc))
        output.seek(0);output.write(json.dumps(result));output.truncate();output.flush();os.fsync(output.fileno())
    print('SCOPE_SIGNED_NO_DEPLOYMENT_OR_MODEL_CALLS')
