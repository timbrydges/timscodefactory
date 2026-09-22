"""Export public enrollment candidates and prove isolated signing; no approval receipts."""
import base64
import hashlib
import json
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from factory_state.kms_signer import (ACCOUNT, ALGORITHM, KEY_ARN, REGION, SIGNERS,
                                     KmsReceiptSigner, assert_role_identity, public_pem)
from factory_state.scope import canonical
from factory_state.signers import public_key_der


class AwsError(RuntimeError):
    def __init__(self, code):
        self.code = code
        super().__init__('AWS operation failed: ' + code)


class AwsJsonClient:
    """Minimal CLI bridge with explicit binary encoding and no credential output."""
    def __init__(self, service):
        self.service = service

    def __getattr__(self, operation):
        if (self.service, operation) not in {('sts', 'get_caller_identity'), ('kms', 'get_public_key'), ('kms', 'sign')}:
            raise AttributeError(operation)
        def call(**params):
            params = {k: base64.b64encode(v).decode() if isinstance(v, bytes) else v for k, v in params.items()}
            result = subprocess.run(['aws', self.service, operation.replace('_', '-'),
                '--region', REGION, '--cli-binary-format', 'base64', '--cli-input-json', json.dumps(params),
                '--output', 'json', '--no-cli-pager'], capture_output=True, timeout=30)
            if result.returncode:
                code = re.search(rb'An error occurred \(([^)]+)\)', result.stderr)
                raise AwsError(code.group(1).decode() if code else 'unclassified-cli-error')
            response = json.loads(result.stdout)
            for field in ('PublicKey', 'Signature'):
                if field in response:
                    response[field] = base64.b64decode(response[field], validate=True)
            return response
        return call


def run(signer, run_id, commit, *, kms=None, sts=None, now=None):
    if signer not in SIGNERS or not re.fullmatch(r'[0-9]+-[0-9]+', run_id) or not re.fullmatch(r'[a-f0-9]{40}', commit):
        raise ValueError('exact signer, workflow run and commit required')
    kms, sts = kms or AwsJsonClient('kms'), sts or AwsJsonClient('sts')
    caller = assert_role_identity(sts, signer)
    # Aliases are used only for bootstrap discovery, never for production receipt signing.
    response = kms.get_public_key(KeyId=f'alias/tims-factory-signing-{signer}')
    key_arn = response.get('KeyId', '')
    if not KEY_ARN.fullmatch(key_arn):
        raise ValueError('unexpected key account or region')
    pem = public_pem(response, expected_arn=key_arn)
    fingerprint = 'sha256:' + hashlib.sha256(public_key_der(pem)).hexdigest()
    now = now or datetime.now(timezone.utc)
    challenge = {'kind': 'identity_challenge', 'identity': SIGNERS[signer],
        'source_commit': commit, 'workflow_run': run_id, 'issued_at': int(now.timestamp()),
        'expires_at': int(now.timestamp()) + 600, 'purpose': 'key-custody-verification-only'}
    adapter = KmsReceiptSigner(kms, sts, signer=signer, key_arn=key_arn, expected_fingerprint=fingerprint)
    signature = adapter.sign(challenge, now=now)
    denied = []
    for other in SIGNERS:
        if other == signer:
            continue
        try:
            kms.sign(KeyId=f'alias/tims-factory-signing-{other}', Message=canonical(challenge),
                     MessageType='RAW', SigningAlgorithm=ALGORITHM)
        except AwsError as error:
            if error.code != 'AccessDeniedException':
                raise
            denied.append(other)
        else:
            raise RuntimeError('cross-role signing unexpectedly succeeded')
    return {'schema_version': '1.0', 'conclusion': 'success', 'source_commit': commit,
        'workflow_run': run_id, 'signer': signer, 'identity': SIGNERS[signer], 'aws_caller_arn': caller,
        'key_arn': key_arn, 'public_key_pem': pem.decode(), 'fingerprint': fingerprint,
        'challenge': challenge, 'signature_base64': base64.b64encode(signature).decode(),
        'cross_role_signing_denied': denied, 'enrollment_status': 'CANDIDATE_REQUIRES_REVIEW',
        'model_calls': 0, 'approval_receipts_created': 0, 'continuous_worker_activated': False}


if __name__ == '__main__':
    print(json.dumps(run(*sys.argv[1:]), indent=2))
