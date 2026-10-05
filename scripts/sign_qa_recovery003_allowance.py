"""Sign one exact owner-reviewed recovery plan. No deployment or model invocation."""
import argparse
import base64
import json
import os
import sys
from datetime import datetime,timezone
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'src'))
from build_qa_recovery003_activation_package import validate_material
from build_qa_recovery003_package import MATERIAL
from factory_runtime.qa_recovery003 import CANDIDATE,CAP,PK,TABLE,SCOPE_SHA256
from factory_runtime.qa_recovery003_authorization import KIND,verify
from factory_runtime.qa_recovery003_adapter import Pilot002Adapter
from factory_runtime.pilot002_packets import digest
from factory_runtime.qa_recovery003_protocols import request_bytes
from factory_runtime.pilot002_entrypoint import _pairs
from factory_state.kms_signer import ALGORITHM,EnrolledKmsReceiptSigner,KmsReceiptSigner,assert_role_identity
from factory_state.model import OWNER_IDENTITY,StateError
from factory_state.scope import canonical


def context(doc):
    return {'source_commit':doc['source_commit'],'candidate_commit':CANDIDATE,
        'builder_response':base64.b64decode(doc['builder_response_base64'],validate=True)}


def validate_plan(plan,*,root,approved_digest,now):
    fields={'status','kind','activation','activation_sha256','pricing','allowance_payload',
        'allowance_payload_digest','evidence','kms_key_arn'}
    if (type(plan) is not dict or set(plan)!=fields or digest(plan)!=approved_digest or
            plan['kind']!='qa_recovery003_signing_plan' or
            plan['status']!='UNSIGNED_REVIEW_CANDIDATE_NOT_AUTHORIZATION'):
        raise StateError('Exact owner-reviewed recovery signing plan required')
    doc=plan['activation'];files={name:(root/name).read_bytes() for name in MATERIAL}
    files['BUILD.json']=canonical({'source_commit':doc['source_commit']})
    material=validate_material(files,canonical(doc),now)
    if material['activation_sha256']!=plan['activation_sha256']:raise StateError('Recovery activation changed')
    registry=json.loads((root/'factory/profiles/scope-signers.json').read_bytes())
    registry['signers']=[entry for entry in registry['signers'] if entry['identity']==OWNER_IDENTITY]
    if canonical(registry)!=canonical(doc['signer_registry']):raise StateError('Owner enrollment changed')
    if doc['readiness']['evidence_digest']!=digest(plan['evidence']):raise StateError('Recovery readiness evidence changed')
    bound=context(doc)
    adapter=Pilot002Adapter(root,role='qa',**bound,qualification=doc['qualification'],clock=lambda:now,enabled=False)
    price=adapter.pricing
    if canonical(price)!=canonical(plan['pricing']):raise StateError('Recovery pricing changed')
    bindings={k:price[k] for k in ('role','model_id','task_id','source_commit','contract_digest','packet_digest','request_digest')}
    expected={'kind':KIND,'owner_identity':OWNER_IDENTITY,**bindings,'candidate_commit':CANDIDATE,
        'recovery_scope_digest':'sha256:'+SCOPE_SHA256,'attempt_table':TABLE,'attempt_key':PK,
        'pricing_digest':digest(price),'readiness_digest':digest(doc['readiness']),
        'reserved_micro_usd':CAP,'approved_cap_micro_usd':CAP,'maximum_provider_calls':1,'retries':0,
        'task_state_writes':0,'capture_failed_review_response':True,'maximum_captured_response_bytes':262144,
        'gate_authority':False,'production_release_authorized':False,
        'issued_at':doc['readiness']['issued_at'],'expires_at':min(material['material_expires_at'],doc['readiness']['expires_at'])}
    payload=plan['allowance_payload']
    if canonical(payload)!=canonical(expected) or digest(payload)!=plan['allowance_payload_digest']:
        raise StateError('Recovery allowance scope changed')
    if not payload['issued_at']<=now.timestamp()<payload['expires_at']-60:raise StateError('Recovery signing window too short')
    return payload


def sign(plan,*,root,approved_digest,kms,sts,now):
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
    try:
        response=kms.sign(KeyId=binding['key_arn'],Message=raw,MessageType='RAW',SigningAlgorithm=ALGORITHM)
        if response.get('KeyId')!=binding['key_arn'] or response.get('SigningAlgorithm')!=ALGORITHM:raise ValueError('signing response')
        envelope={'payload':payload,'signature':base64.b64encode(response['Signature']).decode()}
        bound=context(plan['activation'])
        request=request_bytes(root,role='qa',builder_response=bound['builder_response'],candidate_commit=CANDIDATE)
        verify(envelope,root=root,**bound,request_bytes=request,pricing=plan['pricing'],
            readiness=plan['activation']['readiness'],trusted_keys={OWNER_IDENTITY:pem},now=now)
    except Exception:
        raise StateError('Recovery signing stopped; reconcile without retry') from None
    return envelope


def input_plan(encoded):
    """Decode bounded public QA material as data; no committed stale fallback."""
    if type(encoded) is not str or not 0<len(encoded)<=65536:
        raise StateError('Bounded fresh QA recovery plan required')
    try:
        raw=base64.b64decode(encoded,validate=True)
        if not 0<len(raw)<=49152:raise ValueError('size')
        plan=json.loads(raw,object_pairs_hook=_pairs)
        if type(plan) is not dict:raise ValueError('object')
        return plan
    except (ValueError,TypeError):
        raise StateError('Malformed fresh QA recovery plan') from None


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('output',type=Path)
    parser.add_argument('--approved-plan-digest',required=True);args=parser.parse_args()
    plan=input_plan(os.environ.get('QA_RECOVERY003_PLAN_BASE64',''))
    validate_plan(plan,root=ROOT,approved_digest=args.approved_plan_digest,now=datetime.now(timezone.utc))
    import boto3
    from botocore.config import Config
    config=Config(connect_timeout=5,read_timeout=30,retries={'total_max_attempts':1})
    session=boto3.Session(region_name='ca-central-1')
    with args.output.open('x',encoding='utf-8') as output:
        output.write('{"status":"SIGNING_STARTED_NO_RETRY"}\n');output.flush()
        result=sign(plan,root=ROOT,approved_digest=args.approved_plan_digest,
            kms=session.client('kms',config=config),sts=session.client('sts',config=config),now=datetime.now(timezone.utc))
        output.seek(0);output.truncate();json.dump(result,output,indent=2)
    print('Exact recovery allowance signed; no deployment or model call')
