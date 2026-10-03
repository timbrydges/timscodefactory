"""Sign only an explicitly human-approved zero-dollar proposal; never invoke QA.

The approved-digest argument records operator confirmation, not consent by itself.
The operator must obtain the user's exact approval and recheck unlinked Google
billing before running this script. No production invocation is part of signing.
"""
import argparse
import base64
import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path

from prepare_google_qa_free_allowance import ROOT, proposal
from factory_runtime.google_qa_authorization import digest, verify
from factory_runtime.google_qa_broker_runtime import configuration
from factory_runtime.review_preparation import prepare
from factory_state.kms_signer import ALGORITHM, EnrolledKmsReceiptSigner, KmsReceiptSigner, assert_role_identity
from factory_state.model import StateError
from factory_state.scope import canonical


def sign_proposal(payload, *, root, source_commit, approved_digest, kms, sts, now):
    try:
        if (now.tzinfo is None or now.utcoffset() is None or
                not isinstance(payload,dict) or digest(payload)!=approved_digest or
                type(payload.get('issued_at')) is not int or type(payload.get('expires_at')) is not int or
                not payload['issued_at']<=now.timestamp()<payload['expires_at']):
            raise StateError('owner-approved proposal digest or lifetime differs')
        expected=proposal(root,source_commit=source_commit,billing=payload['billing_evidence'],
            now=datetime.fromtimestamp(payload['issued_at'],timezone.utc))
        if canonical(payload)!=canonical(expected):
            raise StateError('owner proposal differs from exact zero-dollar scope')
        pricing,keys=configuration(root,now)
        adapter=EnrolledKmsReceiptSigner(kms,sts,signer='owner',
            registry_path=root/'factory/profiles/scope-signers.json',
            bindings_path=root/'factory/profiles/kms-signers.json')
        binding,pem=adapter._enrollment(now)
        signer=KmsReceiptSigner(kms,sts,signer='owner',key_arn=binding['key_arn'],expected_fingerprint=binding['fingerprint'])
        if signer.pem!=pem or adapter._enrollment(now)!=(binding,pem):
            raise StateError('owner enrollment changed before signing')
        raw=canonical(payload)
        if len(raw)>4096: raise StateError('owner allowance exceeds KMS RAW bound')
        assert_role_identity(sts,'owner')
        response=kms.sign(KeyId=binding['key_arn'],Message=raw,MessageType='RAW',SigningAlgorithm=ALGORITHM)
        if response.get('KeyId')!=binding['key_arn'] or response.get('SigningAlgorithm')!=ALGORITHM:
            raise StateError('owner signing response identity differs')
        envelope={'payload':payload,'signature':base64.b64encode(response['Signature']).decode()}
        verify(envelope,packet=prepare(root,role='qa'),root=root,source_commit=source_commit,
            pricing=pricing,trusted_keys=keys,now=now)
        return envelope
    except Exception:
        raise StateError('owner allowance signing rejected or uncertain; do not retry automatically') from None


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('proposal',type=Path); parser.add_argument('output',type=Path)
    parser.add_argument('--approved-digest',required=True)
    parser.add_argument('--target-source-commit',required=True)
    args=parser.parse_args()
    if subprocess.check_output(['git','status','--porcelain'],cwd=ROOT,text=True).strip():
        raise RuntimeError('owner signing requires a clean reviewed checkout')
    import boto3
    from botocore.config import Config
    config=Config(connect_timeout=5,read_timeout=30,retries={'total_max_attempts':1})
    # An existing isolated owner session must be provided by the operator. This
    # command neither assumes roles nor creates or expands IAM/KMS permissions.
    session=boto3.Session(region_name='ca-central-1')
    with args.output.open('x',encoding='utf-8') as output:
        output.write('{"status":"SIGNING_STARTED_NO_RETRY"}\n'); output.flush()
        envelope=sign_proposal(json.loads(args.proposal.read_bytes()),root=ROOT,
            source_commit=args.target_source_commit,approved_digest=args.approved_digest,
            kms=session.client('kms',config=config),sts=session.client('sts',config=config),
            now=datetime.now(timezone.utc))
        output.seek(0); output.truncate(); json.dump(envelope,output,indent=2)
    print('SIGNED_ZERO_DOLLAR_ALLOWANCE: no model invocation or task transition')
