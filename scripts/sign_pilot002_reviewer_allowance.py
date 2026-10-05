"""Sign one exact reviewed reviewer plan; never deploy or invoke a worker."""
import argparse
import base64
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'src'))
from factory_runtime.pilot002_adapter import Pilot002Adapter
from factory_runtime.pilot002_authorization import validate_readiness, verify
from factory_runtime.pilot002_packets import digest
from factory_runtime.pilot002_protocols import request_bytes
from factory_runtime.pilot002_entrypoint import _pairs
from factory_state.kms_signer import ALGORITHM, EnrolledKmsReceiptSigner, KmsReceiptSigner, assert_role_identity
from factory_state.scope import canonical
from factory_state.model import StateError

SOURCE='d9c75eb8b59c3c6bda508557224fd92354f8d34c'
QA_SOURCE='013a2141a6985055601a5eb8ff2ccf2ec041e15d'
CANDIDATE='09c789a902377cb095c20abae89459c4cec3e89e'
REQUESTS={
    'inspector':'sha256:28d292a891a23de0ce6786b758f4d9d1982f8cbf744549a6513514c76233ae0a',
    'qa':'sha256:6891cd13c024807b3d02ff30e6f5872207deeeb38f4c7fd23b7ec825c6ef4ed7'}
GOOGLE_ROUTE={'kind':'secretsmanager',
    'secret_arn':'arn:aws:secretsmanager:ca-central-1:666730517561:secret:tims-software-factory/provider/google/qa-rYGeOE',
    'version_id':'db69f4bf-38c0-43d5-8bbf-ce20d8e07282','json_key':None}


def context(doc):
    return {'role':doc['role'],'source_commit':doc['source_commit'],
        'builder_response':base64.b64decode(doc['builder_response_base64'],validate=True),
        'candidate_commit':doc['candidate_commit']}


def validate_plan(plan, *, root, role, approved_digest, now):
    if (role not in REQUESTS or digest(plan)!=approved_digest or
            plan.get('status')!='UNSIGNED_REVIEW_CANDIDATE_NOT_AUTHORIZATION'):
        raise StateError('Exact owner-reviewed reviewer plan required')
    doc=plan['activation'];payload=plan['allowance_payload']
    source=QA_SOURCE if role=='qa' else SOURCE
    if doc['role']!=role or doc['source_commit']!=source or doc['candidate_commit']!=CANDIDATE:
        raise StateError('Reviewed reviewer source and candidate required')
    route={'kind':'lambda_execution_role'} if role=='inspector' else GOOGLE_ROUTE
    if canonical(doc['credential'])!=canonical(route):raise StateError('Credential route changed')
    from build_pilot002_runtime_package import _activation, MATERIAL
    files={name:(root/name).read_bytes() for name in MATERIAL}
    files['BUILD.json']=canonical({'source_commit':source})
    material=_activation(files,canonical(doc),now)
    if material['activation_sha256']!=plan['activation_sha256']:raise StateError('Activation changed')
    bound=context(doc)
    raw=request_bytes(root,**{k:v for k,v in bound.items() if k!='source_commit'})
    if 'sha256:'+hashlib.sha256(raw).hexdigest()!=REQUESTS[role]:raise StateError('Counted request changed')
    adapter=Pilot002Adapter(root,**bound,qualification=doc['qualification'],clock=lambda:now,enabled=False)
    price=adapter.pricing
    if canonical(price)!=canonical(plan['pricing']):raise StateError('Pricing changed')
    # This path does not authorize linking billing or silently using paid Google.
    if role=='qa' and price['kind']!='pilot002_google_free_tier_cost_bound':
        raise StateError('QA requires fresh zero-dollar free-tier qualification')
    bindings={k:price[k] for k in ('role','model_id','task_id','source_commit','contract_digest','packet_digest','request_digest')}
    validate_readiness(doc['readiness'],bindings=bindings,now=now)
    if doc['readiness']['kind']!='pilot002_reviewer_first_generation_readiness':
        raise StateError('Explicit first-generation reviewer risk acceptance required')
    expected={'kind':'pilot002_exact_request_allowance','owner_identity':'tim_brydges',**bindings,
        'pricing_digest':digest(price),'readiness_digest':digest(doc['readiness']),
        'reserved_micro_usd':250000,'approved_cap_micro_usd':250000,'maximum_provider_calls':1,
        'retries':0,'task_state_writes':0,'gate_authority':False,'production_release_authorized':False,
        'issued_at':doc['readiness']['issued_at'],'expires_at':doc['readiness']['expires_at']}
    if canonical(payload)!=canonical(expected) or digest(payload)!=plan['allowance_payload_digest']:
        raise StateError('Allowance scope changed')
    if not payload['issued_at']<=now.timestamp()<payload['expires_at']<=price['expires_at']:
        raise StateError('Allowance expired')
    registry=json.loads((root/'factory/profiles/scope-signers.json').read_bytes())
    registry['signers']=[entry for entry in registry['signers'] if entry['identity']=='tim_brydges']
    if canonical(registry)!=canonical(doc['signer_registry']):raise StateError('Owner enrollment changed')
    if doc['readiness']['evidence_digest']!=digest(plan['evidence']):raise StateError('Evidence changed')
    return payload


def sign(plan, *, root, role, approved_digest, kms, sts, now):
    payload=validate_plan(plan,root=root,role=role,approved_digest=approved_digest,now=now)
    enrollment=EnrolledKmsReceiptSigner(kms,sts,signer='owner',
        registry_path=root/'factory/profiles/scope-signers.json',bindings_path=root/'factory/profiles/kms-signers.json')
    binding,pem=enrollment._enrollment(now)
    if binding['key_arn']!=plan['kms_key_arn']:raise StateError('Owner KMS key changed')
    signer=KmsReceiptSigner(kms,sts,signer='owner',key_arn=binding['key_arn'],expected_fingerprint=binding['fingerprint'])
    if signer.pem!=pem:raise StateError('Owner public key changed')
    raw=canonical(payload)
    if len(raw)>4096:raise StateError('KMS RAW bound exceeded')
    assert_role_identity(sts,'owner')
    try:
        response=kms.sign(KeyId=binding['key_arn'],Message=raw,MessageType='RAW',SigningAlgorithm=ALGORITHM)
        if response.get('KeyId')!=binding['key_arn'] or response.get('SigningAlgorithm')!=ALGORITHM:
            raise ValueError('signing response')
        envelope={'payload':payload,'signature':base64.b64encode(response['Signature']).decode()}
        bound=context(plan['activation'])
        request=request_bytes(root,**{k:v for k,v in bound.items() if k!='source_commit'})
        verify(envelope,root=root,**bound,request_bytes=request,pricing=plan['pricing'],
            readiness=plan['activation']['readiness'],trusted_keys={'tim_brydges':pem},now=now)
    except Exception:
        raise StateError('Reviewer signing stopped; reconcile without retry') from None
    return envelope


def read_plan(path):
    with path.open('rb') as stream:raw=stream.read(131073)
    if not 0<len(raw)<=131072:raise StateError('Reviewer plan exceeds bound')
    return json.loads(raw,object_pairs_hook=_pairs)


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('role',choices=tuple(REQUESTS));parser.add_argument('output',type=Path)
    parser.add_argument('--approved-plan-digest',required=True);args=parser.parse_args()
    plan=read_plan(ROOT/f'factory/evidence/pilot-002-{args.role}-live-review-candidate.json')
    now=datetime.now(timezone.utc)
    validate_plan(plan,root=ROOT,role=args.role,approved_digest=args.approved_plan_digest,now=now)
    import boto3
    from botocore.config import Config
    config=Config(connect_timeout=5,read_timeout=30,retries={'total_max_attempts':1})
    session=boto3.Session(region_name='ca-central-1')
    with args.output.open('x',encoding='utf-8') as output:
        output.write('{"status":"SIGNING_STARTED_NO_RETRY"}\n');output.flush()
        result=sign(plan,root=ROOT,role=args.role,approved_digest=args.approved_plan_digest,
            kms=session.client('kms',config=config),sts=session.client('sts',config=config),now=datetime.now(timezone.utc))
        output.seek(0);output.truncate();json.dump(result,output,indent=2)
    print('Exact reviewer allowance signed; no deployment, invocation or model call')
