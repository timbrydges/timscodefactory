"""Sign one bounded fresh handoff plan; no deployment or provider calls."""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from datetime import datetime, timezone

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'src'))
from factory_runtime.handoff001_entrypoint import load_activation, ACTIVATION
from factory_runtime.handoff001_packets import PINNED, digest
from factory_runtime.handoff001_receipts import IDENTITIES
from factory_runtime.pilot002_entrypoint import _pairs
from factory_state.kms_signer import ALGORITHM, EnrolledKmsReceiptSigner, KmsReceiptSigner, assert_role_identity
from factory_state.model import OWNER_IDENTITY, StateError
from factory_state.scope import canonical


def material(doc, root, now, *, unsigned):
    """Use the same activation validation as Lambda, with isolated public files."""
    raw = canonical(doc)
    with tempfile.TemporaryDirectory() as directory:
        target = Path(directory)
        for name in PINNED:
            path = target/name; path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes((root/name).read_bytes())
        (target/'BUILD.json').write_bytes(canonical({'source_commit': doc['source_commit']}))
        (target/ACTIVATION).write_bytes(raw)
        return load_activation(target, {'FACTORY_HANDOFF001_ROLE': doc['role'],
            'FACTORY_HANDOFF001_ACTIVATION_SHA256': hashlib.sha256(raw).hexdigest()},
            now, allow_unsigned=unsigned)


def validate_plan(plan, *, root, approved_digest, source_commit, now):
    if (type(plan) is not dict or set(plan) != {'kind', 'activation', 'evidence'} or
            plan['kind'] != 'handoff001_owner_signing_plan' or digest(plan) != approved_digest):
        raise StateError('Exact reviewed handoff plan required')
    doc = plan['activation']
    if doc.get('source_commit') != source_commit:
        raise StateError('Handoff source differs from reviewed workflow checkout')
    registry = json.loads((root/'factory/profiles/scope-signers.json').read_bytes())
    required = {OWNER_IDENTITY, *IDENTITIES.values()}
    registry['signers'] = [item for item in registry['signers'] if item['identity'] in required]
    if canonical(registry) != canonical(doc.get('signer_registry')):
        raise StateError('Handoff enrollment differs from reviewed registry')
    if (type(plan['evidence']) is not dict or set(plan['evidence']) != {'pricing', 'readiness'} or
            doc['qualification']['evidence_digest'] != digest(plan['evidence']['pricing']) or
            doc['readiness']['evidence_digest'] != digest(plan['evidence']['readiness'])):
        raise StateError('Handoff evidence bindings differ')
    material(doc, root, now, unsigned=True)
    payload = doc['allowance']['payload']
    if payload['expires_at'] - now.timestamp() < 300:
        raise StateError('Insufficient fresh signing window')
    return payload


def sign(plan, *, root, approved_digest, source_commit, kms, sts, now):
    payload = validate_plan(plan, root=root, approved_digest=approved_digest, source_commit=source_commit, now=now)
    enrollment = EnrolledKmsReceiptSigner(kms, sts, signer='owner',
        registry_path=root/'factory/profiles/scope-signers.json', bindings_path=root/'factory/profiles/kms-signers.json')
    binding, pem = enrollment._enrollment(now)
    signer = KmsReceiptSigner(kms, sts, signer='owner', key_arn=binding['key_arn'], expected_fingerprint=binding['fingerprint'])
    if signer.pem != pem: raise StateError('Owner public key differs')
    raw = canonical(payload)
    if len(raw) > 4096: raise StateError('Owner signing payload too large')
    assert_role_identity(sts, 'owner')
    response = kms.sign(KeyId=binding['key_arn'], Message=raw, MessageType='RAW', SigningAlgorithm=ALGORITHM)
    if response.get('KeyId') != binding['key_arn'] or response.get('SigningAlgorithm') != ALGORITHM:
        raise StateError('Owner signing response differs; reconcile without retry')
    doc = json.loads(canonical(plan['activation']))
    doc['allowance']['signature'] = base64.b64encode(response['Signature']).decode()
    material(doc, root, now, unsigned=False)
    return doc


def input_plan(encoded):
    if type(encoded) is not str or not 0 < len(encoded) <= 65536:
        raise StateError('Bounded public handoff plan required')
    raw = base64.b64decode(encoded, validate=True)
    if not 0 < len(raw) <= 49152: raise StateError('Handoff plan too large')
    return json.loads(raw, object_pairs_hook=_pairs)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('output', type=Path)
    parser.add_argument('--approved-plan-digest', required=True)
    args = parser.parse_args()
    plan = input_plan(os.environ.get('HANDOFF001_PLAN_BASE64', ''))
    source = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip()
    if source != os.environ.get('GITHUB_SHA') or os.environ.get('GITHUB_RUN_ATTEMPT') != '1':
        raise SystemExit('Reviewed first-attempt workflow required')
    import boto3
    from botocore.config import Config
    config = Config(retries={'total_max_attempts': 1}, connect_timeout=5, read_timeout=30)
    session = boto3.Session(region_name='ca-central-1')
    with args.output.open('x', encoding='utf-8') as output:
        output.write('{"status":"SIGNING_STARTED_NO_RETRY"}\n'); output.flush(); os.fsync(output.fileno())
        result = sign(plan, root=ROOT, approved_digest=args.approved_plan_digest, source_commit=source,
            kms=session.client('kms', config=config), sts=session.client('sts', config=config), now=datetime.now(timezone.utc))
        output.seek(0); json.dump(result, output); output.truncate(); output.flush(); os.fsync(output.fileno())
    print('HANDOFF_ACTIVATION_SIGNED_NO_DEPLOYMENT_OR_MODEL_CALLS')
