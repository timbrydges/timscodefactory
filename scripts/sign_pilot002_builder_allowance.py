"""Sign the exact reviewed Builder candidate once in the isolated owner workflow."""
import argparse
import base64
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
from factory_state.kms_signer import ALGORITHM, EnrolledKmsReceiptSigner, KmsReceiptSigner, assert_role_identity
from factory_state.scope import canonical
from factory_state.model import StateError


def validate_plan(plan, *, root, approved_digest, now):
    if digest(plan)!=approved_digest or plan.get('status')!='UNSIGNED_REVIEW_CANDIDATE_NOT_AUTHORIZATION':
        raise StateError('Exact owner-reviewed plan required')
    doc=plan['activation']; payload=plan['allowance_payload']
    if doc['role']!='builder' or doc['source_commit']!='535233c6e7e7655ef79e885b9c1a164fd7bee1d4':
        raise StateError('Reviewed Builder source required')
    from build_pilot002_runtime_package import _activation,MATERIAL
    files={name:(root/name).read_bytes() for name in MATERIAL}
    files['BUILD.json']=canonical({'source_commit':doc['source_commit']})
    material=_activation(files,canonical(doc),now)
    if material['activation_sha256']!=plan['activation_sha256']:
        raise StateError('Activation changed')
    adapter=Pilot002Adapter(root,role='builder',source_commit=doc['source_commit'],
        qualification=doc['qualification'],clock=lambda:now,enabled=False)
    price=adapter.pricing
    if canonical(price)!=canonical(plan['pricing']):raise StateError('Pricing changed')
    bindings={k:price[k] for k in ('role','model_id','task_id','source_commit','contract_digest','packet_digest','request_digest')}
    validate_readiness(doc['readiness'],bindings=bindings,now=now)
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


def sign(plan, *, root, approved_digest, kms, sts, now):
    payload=validate_plan(plan,root=root,approved_digest=approved_digest,now=now)
    enrollment=EnrolledKmsReceiptSigner(kms,sts,signer='owner',
        registry_path=root/'factory/profiles/scope-signers.json',bindings_path=root/'factory/profiles/kms-signers.json')
    binding,pem=enrollment._enrollment(now)
    if binding['key_arn']!=plan['kms_key_arn']:raise StateError('Owner KMS key changed')
    signer=KmsReceiptSigner(kms,sts,signer='owner',key_arn=binding['key_arn'],expected_fingerprint=binding['fingerprint'])
    if signer.pem!=pem:raise StateError('Owner public key changed')
    raw=canonical(payload)
    if len(raw)>4096:raise StateError('KMS RAW bound exceeded')
    assert_role_identity(sts,'owner')
    response=kms.sign(KeyId=binding['key_arn'],Message=raw,MessageType='RAW',SigningAlgorithm=ALGORITHM)
    if response.get('KeyId')!=binding['key_arn'] or response.get('SigningAlgorithm')!=ALGORITHM:
        raise StateError('Signing response changed; do not retry')
    envelope={'payload':payload,'signature':base64.b64encode(response['Signature']).decode()}
    verify(envelope,root=root,role='builder',request_bytes=request_bytes(root,role='builder'),
        source_commit=plan['activation']['source_commit'],pricing=plan['pricing'],
        readiness=plan['activation']['readiness'],trusted_keys={'tim_brydges':pem},now=now)
    return envelope


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('output',type=Path);parser.add_argument('--approved-plan-digest',required=True)
    args=parser.parse_args()
    import boto3
    from botocore.config import Config
    config=Config(connect_timeout=5,read_timeout=30,retries={'total_max_attempts':1})
    session=boto3.Session(region_name='ca-central-1')
    plan=json.loads((ROOT/'factory/evidence/pilot-002-builder-live-review-candidate.json').read_bytes())
    with args.output.open('x',encoding='utf-8') as output:
        output.write('{"status":"SIGNING_STARTED_NO_RETRY"}\n');output.flush()
        result=sign(plan,root=ROOT,approved_digest=args.approved_plan_digest,
            kms=session.client('kms',config=config),sts=session.client('sts',config=config),now=datetime.now(timezone.utc))
        output.seek(0);output.truncate();json.dump(result,output,indent=2)
    print('Exact Builder allowance signed; no deployment, invocation or model call')
