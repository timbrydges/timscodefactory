"""Inert S3 IAM canary from one isolated signing role.

Writes one invalid, non-approval object under a random digest. The receipt
transport cannot accept this body as an approval. No model or secret IO.
"""
from __future__ import annotations

import hashlib
import json
import re
import subprocess
import sys
import tempfile
import uuid
from pathlib import Path

ACCOUNT = '666730517561'
REGION = 'ca-central-1'
BUCKET = f'tims-software-factory-{ACCOUNT}-{REGION}'
ROLES = {'owner': 'tims-factory-signing-owner',
         'reviewer': 'tims-factory-signing-inspector'}


def aws(service, action, *args, expect_denied=False):
    result = subprocess.run(['aws', service, action, *args, '--region', REGION,
                             '--output', 'json', '--no-cli-pager'],
                            capture_output=True, text=True, timeout=60)
    if expect_denied:
        if result.returncode == 0 or 'AccessDenied' not in result.stderr:
            raise RuntimeError('cross-role or unencrypted receipt write was not denied')
        return None
    if result.returncode:
        raise RuntimeError(f'{service} {action} failed: {result.stderr.strip()}')
    return json.loads(result.stdout or '{}')


def canary(kind, run_id, source_commit):
    if (kind not in ROLES or not re.fullmatch(r'[0-9]+-[0-9]+', run_id) or
            not re.fullmatch(r'[a-f0-9]{40}', source_commit)):
        raise RuntimeError('invalid receipt canary identity or source')
    caller = aws('sts', 'get-caller-identity')
    expected = f'arn:aws:sts::{ACCOUNT}:assumed-role/{ROLES[kind]}/'
    if (caller.get('Account') != ACCOUNT or
            not caller.get('Arn', '').startswith(expected)):
        raise RuntimeError('receipt canary assumed unexpected identity')
    nonce = uuid.uuid4().hex
    digest = hashlib.sha256(f'receipt-iam-canary:{kind}:{run_id}:{nonce}'.encode()).hexdigest()
    document = json.dumps({'kind': 'receipt_iam_canary_not_approval',
                           'source_commit': source_commit, 'run_id': run_id,
                           'nonce': nonce}, separators=(',', ':'), sort_keys=True).encode()
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / 'inert-canary.json'
        path.write_bytes(document)
        own_key = f'factory-scope-receipts/{digest}/{kind}.json'
        other = 'reviewer' if kind == 'owner' else 'owner'
        cross_key = f'factory-scope-receipts/{digest}/{other}.json'
        base = ('--bucket', BUCKET, '--body', str(path), '--if-none-match', '*')
        own = aws('s3api', 'put-object', *base, '--key', own_key,
                  '--server-side-encryption', 'AES256', '--checksum-algorithm', 'SHA256')
        if (not isinstance(own.get('VersionId'), str) or not own['VersionId'] or
                own['VersionId'] == 'null' or own.get('ServerSideEncryption') != 'AES256'):
            raise RuntimeError('receipt canary lacks versioned encrypted write proof')
        aws('s3api', 'put-object', *base, '--key', cross_key,
            '--server-side-encryption', 'AES256', expect_denied=True)
        denied_key = f'factory-scope-receipts/{hashlib.sha256((digest+"unencrypted").encode()).hexdigest()}/{kind}.json'
        aws('s3api', 'put-object', *base, '--key', denied_key, expect_denied=True)
    return {'status': 'INERT_RECEIPT_WRITER_CANARY_VERIFIED', 'kind': kind,
            'source_commit': source_commit, 'run_id': run_id,
            'caller_arn': caller['Arn'], 'object_key': own_key,
            'object_version': own['VersionId'], 'body_sha256': hashlib.sha256(document).hexdigest(),
            'own_encrypted_put': 'allowed', 'cross_put': 'AccessDenied',
            'unencrypted_put': 'AccessDenied', 'approval_receipts_published': 0,
            'inert_canary_objects_published': 1, 'model_calls': 0}


if __name__ == '__main__':
    if len(sys.argv) != 4:
        raise SystemExit('usage: receipt_writer_live_canary.py owner|reviewer RUN_ID-ATTEMPT COMMIT')
    print(json.dumps(canary(*sys.argv[1:]), indent=2))
