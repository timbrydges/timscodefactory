"""Publish one explicitly selected owner scope receipt from the isolated workflow.

No reviewer signature, provider call, task dispatch or activation is performed.
The workflow is off by default and accepts only the owner's exact plan digest.
"""
from __future__ import annotations

import base64
import json
import os
import re
import subprocess
import sys
import tempfile
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))

from factory_runtime.acceptance_jobs import _unique
from factory_runtime.autonomy_contract import load_autonomy_operating_allowance
from factory_runtime.lambda_role import _decode_inspector_live_plan
from factory_runtime.receipt_transport import VersionedS3ReceiptPublisher
from factory_state.kms_signer import EnrolledKmsReceiptSigner, assert_role_identity
from factory_state.model import StateError
from kms_signing_canary import AwsJsonClient


def validate_plan(document, approved_digest, commit, *, now, root=ROOT):
    if (not isinstance(approved_digest, str) or not re.fullmatch(r'sha256:[0-9a-f]{64}', approved_digest) or
            not isinstance(commit, str) or not re.fullmatch('[0-9a-f]{40}', commit) or
            not isinstance(document, dict) or document.get('plan_digest') != approved_digest):
        raise StateError('owner publication requires the exact approved plan digest and source')
    plan = _decode_inspector_live_plan(document, commit=commit, now=now)
    cap, review = plan.capability_payload, plan.review_payload
    if (set(cap) != {'kind', 'factory_id', 'objective_id', 'capability_id', 'contract_digest',
            'owner_identity', 'required_evidence', 'stop_condition', 'issued_at', 'expires_at'} or
            set(review) != {'kind', 'factory_id', 'task_id', 'binding', 'verdict',
            'reviewer_identity', 'rationale', 'issued_at', 'expires_at'} or
            cap['factory_id'] != plan.factory_id or cap['objective_id'] != 'autonomy' or
            cap['capability_id'] != 'acceptance' or review['factory_id'] != plan.factory_id or
            review['task_id'] != plan.task_id or plan.request.lease_id != plan.lease.lease_id or
            plan.state_version < 1 or (plan.lease.expires_at - now).total_seconds() > 3600 or
            any(payload['expires_at'] - payload['issued_at'] > 1800 for payload in (cap, review)) or
            any(not isinstance(value, str) or not value.strip() or len(value) > 2000
                for value in (cap['required_evidence'], cap['stop_condition'], review['rationale']))):
        raise StateError('owner receipt scope or lifetime differs from bounded acceptance')
    allowance = load_autonomy_operating_allowance(root)
    if (allowance.production_release_authorized or allowance.maximum_provider_calls != 3 or
            str(allowance.maximum_cost_per_call) != '0.25' or
            plan.request.contract_digest != 'sha256:' + allowance.acceptance_contract_sha256 or
            not allowance.pricing_observed_at <= now < allowance.pricing_expires_at or
            max(cap['expires_at'], review['expires_at']) > allowance.pricing_expires_at.timestamp()):
        raise StateError('owner receipt differs from current financial and pricing allowance')
    return plan


class CliReceiptWriter:
    meta = SimpleNamespace(config=SimpleNamespace(retries={'total_max_attempts': 1}),
                           endpoint_url='https://s3.ca-central-1.amazonaws.com')

    def put_object(self, **request):
        with tempfile.TemporaryDirectory() as directory:
            body = Path(directory) / 'receipt.json'
            body.write_bytes(request.pop('Body'))
            args = ['aws', 's3api', 'put-object', '--body', str(body),
                    '--cli-input-json', json.dumps(request), '--region', 'ca-central-1',
                    '--output', 'json', '--no-cli-pager']
            result = subprocess.run(args, capture_output=True, text=True, timeout=60,
                env={**os.environ, 'AWS_MAX_ATTEMPTS': '1', 'AWS_PAGER': ''})
        if result.returncode:
            raise StateError('owner receipt publication failed; reconcile the exact object, do not retry')
        return json.loads(result.stdout)


def publish(document, approved_digest, commit, *, now, signer, writer, sts, root=ROOT):
    plan = validate_plan(document, approved_digest, commit, now=now, root=root)
    assert_role_identity(sts, 'owner')
    result = VersionedS3ReceiptPublisher(writer, signer, kind='owner').publish(plan, now=now)
    return {'status': 'OWNER_RECEIPT_PUBLISHED', 'source_commit': commit,
        'publication': asdict(result), 'model_calls': 0, 'reviewer_receipts_published': 0,
        'activation_authorized': False}


def main():
    if len(sys.argv) != 2:
        raise SystemExit('usage: publish_acceptance_owner_receipt.py RESULT.json (isolated workflow only)')
    expected = {'GITHUB_REPOSITORY': 'timbrydges/timscodefactory',
        'GITHUB_ACTOR_ID': '214414801', 'GITHUB_REF': 'refs/heads/main',
        'GITHUB_RUN_ATTEMPT': '1', 'FACTORY_OWNER_PUBLICATION_ENABLED': 'true'}
    if any(os.environ.get(key) != value for key, value in expected.items()):
        raise StateError('owner publication workflow is disabled or identity differs; reruns prohibited')
    encoded = os.environ.get('FACTORY_OWNER_PLAN_BASE64', '')
    if not 0 < len(encoded) <= 24000:
        raise StateError('owner plan exceeds its bound')
    document = json.loads(base64.b64decode(encoded, validate=True), object_pairs_hook=_unique)
    approved = os.environ.get('FACTORY_OWNER_APPROVED_PLAN_DIGEST', '')
    commit = os.environ.get('GITHUB_SHA', '')
    if (subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip() != commit or
            subprocess.check_output(['git', 'status', '--porcelain'], cwd=ROOT, text=True).strip()):
        raise StateError('owner signing checkout differs from workflow source')
    now = datetime.now(timezone.utc)
    validate_plan(document, approved, commit, now=now)
    result_path = Path(sys.argv[1])
    with result_path.open('x', encoding='utf-8') as output:
        json.dump({'status': 'ATTEMPTED_RECONCILE_IF_UNCERTAIN', 'plan_digest': approved,
                   'source_commit': commit, 'model_calls': 0}, output)
    os.environ['AWS_MAX_ATTEMPTS'] = '1'
    sts = AwsJsonClient('sts')
    signer = EnrolledKmsReceiptSigner(AwsJsonClient('kms'), sts, signer='owner',
        registry_path=ROOT / 'factory/profiles/scope-signers.json',
        bindings_path=ROOT / 'factory/profiles/kms-signers.json')
    result = publish(document, approved, commit, now=now, signer=signer,
                     writer=CliReceiptWriter(), sts=sts)
    result_path.write_text(json.dumps(result, sort_keys=True, indent=2) + '\n')
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    main()
