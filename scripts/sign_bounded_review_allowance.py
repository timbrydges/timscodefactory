"""Owner-reviewed exact plan plus independently authenticated Docker material.

Evidence digests bind the owner's reviewed pricing/readiness documents; they do
not establish their truth. The privileged operator must qualify those documents
before dispatch. This command signs only: no credentials, claims or model calls.
"""
import argparse
import base64
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import subprocess
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'src'))
sys.path.insert(0,str(ROOT))
from scripts.prepare_bounded_review_material import prepare
from factory_runtime.review_material import PinnedReviewMaterial
from factory_runtime.review_provider_scope import PROVIDERS, validate_unsigned
from factory_runtime.review_signing import ReviewAllowanceSigner
from factory_runtime.worker import digest
from factory_state.model import StateError
from factory_state.scope import canonical
from factory_state.signers import load_trusted_signers


def decode(encoded):
    if type(encoded)is not str or not 0<len(encoded)<=65536:
        raise StateError('bounded public owner plan required')
    try:
        raw=base64.b64decode(encoded,validate=True)
        if not 0<len(raw)<=49152:raise ValueError('size')
        plan=json.loads(raw)
        if canonical(plan)!=raw:raise ValueError('canonical')
        return plan
    except (ValueError,TypeError):raise StateError('canonical owner plan required') from None


def validate_plan(plan, *, approved_digest, source_commit, root=ROOT, clock, importer=prepare):
    fields={'kind','source_commit','role','proof_run_id','material_digest','pricing','readiness','allowance','evidence'}
    if (type(plan)is not dict or set(plan)!=fields or digest(canonical(plan))!=approved_digest or
            plan['kind']!='bounded_review001_owner_signing_plan' or plan['source_commit']!=source_commit or
            type(plan['role'])is not str or plan['role'] not in PROVIDERS or
            type(plan['proof_run_id'])is not int or plan['proof_run_id']<=0 or
            type(plan['evidence'])is not dict or set(plan['evidence'])!={'pricing','readiness'}):
        raise StateError('exact owner-reviewed fresh plan required')
    for name in ('pricing','readiness'):
        if (type(plan[name])is not dict or type(plan['evidence'][name])is not dict or
                not plan['evidence'][name] or plan[name].get('evidence_digest')!=digest(canonical(plan['evidence'][name]))):
            raise StateError('owner-reviewed evidence binding differs')
    raw=importer(source_commit,plan['proof_run_id'],root=root,clock=clock)
    material=PinnedReviewMaterial.load(raw,expected_digest=plan['material_digest'],
        deployed_commit=source_commit,clock=clock)
    scope=material.prepared(plan['role']).scope
    now=clock()
    validate_unsigned(plan['allowance'],scope=scope,pricing=plan['pricing'],readiness=plan['readiness'],now=now)
    if plan['allowance']['expires_at']-now.timestamp()<300:
        raise StateError('insufficient fresh signing window')
    return scope


def sign_plan(plan, *, approved_digest, source_commit, kms, sts, clock, root=ROOT, importer=prepare):
    scope=validate_plan(plan,approved_digest=approved_digest,source_commit=source_commit,
                        root=root,clock=clock,importer=importer)
    signer=ReviewAllowanceSigner(scope=scope,pricing=plan['pricing'],readiness=plan['readiness'],
        kms=kms,sts=sts,key_loader=lambda now:load_trusted_signers(root/'factory/profiles/scope-signers.json',now=now),
        clock=clock,enabled=True)
    signature=signer.sign(plan['allowance'],now=clock())
    return {'payload':plan['allowance'],'signature_base64':base64.b64encode(signature).decode()}


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('output',type=Path);parser.add_argument('--approved-plan-digest',required=True)
    args=parser.parse_args()
    source=subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip()
    if (source!=os.environ.get('GITHUB_SHA') or os.environ.get('GITHUB_RUN_ATTEMPT')!='1' or
            os.environ.get('GITHUB_REF')!='refs/heads/main' or os.environ.get('GITHUB_ACTOR_ID')!='214414801'):
        raise StateError('first-attempt owner main workflow required')
    plan=decode(os.environ.get('BOUNDED_REVIEW_PLAN_BASE64',''))
    import boto3
    from botocore.config import Config
    config=Config(retries={'total_max_attempts':1},connect_timeout=5,read_timeout=30)
    session=boto3.Session(region_name='ca-central-1')
    with args.output.open('x',encoding='utf-8') as output:
        output.write('{"status":"SIGNING_STARTED_NO_RETRY"}\n');output.flush();os.fsync(output.fileno())
        envelope=sign_plan(plan,approved_digest=args.approved_plan_digest,source_commit=source,
            kms=session.client('kms',config=config),sts=session.client('sts',config=config),
            clock=lambda:datetime.now(timezone.utc))
        output.seek(0);output.write(json.dumps(envelope));output.truncate();output.flush();os.fsync(output.fileno())
    print('FRESH_ALLOWANCE_SIGNED_NO_DEPLOYMENT_OR_MODEL_CALLS')
