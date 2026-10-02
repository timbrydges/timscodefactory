"""Verify live receipt signatures and publish one immutable acceptance job.

Publishing does not attach IAM, change configuration, enable a schedule or
authorize execution. Lost write responses are reconciled by a read, never a retry.
"""
from __future__ import annotations

import base64
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / 'src'), str(ROOT / 'scripts')]

from factory_runtime.acceptance_jobs import MAX_JOB, PinnedJobVersion, _unique
from factory_runtime.autonomy_contract import load_autonomy_operating_allowance
from factory_runtime.receipt_transport import BUCKET, ReceiptVersions, VersionedS3ReceiptTransport, s3_client
from factory_runtime.worker import digest
from factory_state.dynamodb import DynamoDBStateStore
from factory_state.model import COMMIT_SHA, SAFE_IDENTIFIER, SHA256_DIGEST, StateError
from factory_state.scope import SignedScopeStore
from factory_state.signers import load_trusted_signers
from prepare_acceptance_job import prepare
from prepare_role_deployment import ACCOUNT, REGION, source
from publish_acceptance_owner_receipt import validate_plan


def verified_job(binding, document, versions, *, commit, now, s3, states, database, root=ROOT):
    if not isinstance(binding, dict) or binding.get('source_commit') != commit:
        raise StateError('job source differs from the exact clean checkout')
    raw, _ = prepare(binding, document, versions,
        (root / 'factory/autonomy/acceptance-input.txt').read_bytes(),
        (root / 'factory/autonomy/acceptance-contract.json').read_bytes(), now=now)
    plan = validate_plan(document, document['plan_digest'], commit, now=now, root=root)
    if datetime.fromisoformat(binding['expires_at']) > load_autonomy_operating_allowance(root).pricing_expires_at:
        raise StateError('job activation outlives the verified pricing window')
    if any(value == 'NOT_PUBLISHED' for value in versions.values()):
        raise StateError('published receipt versions are required')
    state = states.load_state(plan.factory_id, plan.task_id)
    if (state is None or (state.factory_id, state.task_id, state.state, state.version) !=
            (plan.factory_id, plan.task_id, plan.state, plan.state_version) or state.leases):
        raise StateError('job plan no longer matches an unleased authoritative task')
    budget = database.get_item(TableName='tims-factory-acceptance-budget',
        Key={'PK': {'S': 'ACTIVATION#' + binding['activation_id']}, 'SK': {'S': 'BUDGET'}},
        ConsistentRead=True)
    if budget.get('Item'):
        raise StateError('job activation budget is already present; never reset or reuse it')
    receipts = VersionedS3ReceiptTransport(s3).load(plan, ReceiptVersions(**versions))
    scope = SignedScopeStore('unused', None,
        load_trusted_signers(root / 'factory/profiles/scope-signers.json', now=now))
    scope._verify(plan.capability_payload, receipts.owner_signature, 'tim_brydges', now)
    scope._verify(plan.review_payload, receipts.reviewer_signature, 'independent_inspector_service', now)
    return raw, {'receipt_plan_digest': receipts.plan_digest,
        'owner_receipt_version': versions['owner'], 'reviewer_receipt_version': versions['reviewer'],
        'task_state_version': state.version, 'job_sha256': digest(raw)}


def _key(activation):
    return f'factory-autonomy-jobs/{activation}/IMPLEMENTATION.json'


def publish(raw, binding, proof, journal_path, *, now, s3):
    VersionedS3ReceiptTransport(s3)  # Enforce regional, no-retry IO before writing.
    if not isinstance(raw, bytes) or not 0 < len(raw) <= MAX_JOB or digest(raw) != proof['job_sha256']:
        raise StateError('publication bytes differ from verified job')
    # Create before the write. A timeout or process interruption leaves an
    # explicit uncertain result, and exclusive creation prevents replay.
    journal = {'status': 'ATTEMPTED_RECONCILE_REQUIRED', 'prepared_at': now.isoformat(),
        'source_commit': binding['source_commit'], 'activation_id': binding['activation_id'],
        'bucket': BUCKET, 'key': _key(binding['activation_id']),
        'job_sha256': digest(raw), 'proof': proof,
        'model_calls': 0, 'activation_authorized': False}
    with Path(journal_path).open('x', encoding='utf-8') as output:
        output.write(json.dumps(journal, sort_keys=True, indent=2) + '\n')
    response = s3.put_object(Bucket=BUCKET, Key=journal['key'], Body=raw,
        ContentType='application/json', ServerSideEncryption='AES256', IfNoneMatch='*',
        ChecksumSHA256=base64.b64encode(hashlib.sha256(raw).digest()).decode(),
        Metadata={'activation-id': binding['activation_id'], 'source-commit': binding['source_commit'],
                  'plan-digest': proof['receipt_plan_digest']})
    pin = PinnedJobVersion(response.get('VersionId'), digest(raw))
    journal.update(status='JOB_PUBLISHED_NOT_ACTIVATED', job_version_id=pin.version_id)
    Path(journal_path).write_text(json.dumps(journal, sort_keys=True, indent=2) + '\n')
    return journal


def reconcile(journal_path, *, s3):
    """Read the result of an attempted put; this does not reauthorize expired scope."""
    journal = json.loads(Path(journal_path).read_text(), object_pairs_hook=_unique)
    VersionedS3ReceiptTransport(s3)
    if (journal.get('status') not in {'ATTEMPTED_RECONCILE_REQUIRED', 'JOB_PUBLISHED_NOT_ACTIVATED'} or
            not isinstance(journal.get('activation_id'), str) or
            not SAFE_IDENTIFIER.fullmatch(journal['activation_id']) or
            not isinstance(journal.get('source_commit'), str) or
            not COMMIT_SHA.fullmatch(journal['source_commit']) or
            not isinstance(journal.get('job_sha256'), str) or
            not SHA256_DIGEST.fullmatch(journal['job_sha256']) or
            journal.get('bucket') != BUCKET or
            journal.get('key') != _key(journal.get('activation_id')) or
            journal.get('model_calls') != 0 or journal.get('activation_authorized') is not False):
        raise StateError('job publication journal differs from the bounded attempt')
    # Latest is read only when the response did not supply a version. The
    # returned immutable version, checksum and complete bytes must all match.
    params = {'Bucket': BUCKET, 'Key': journal['key'], 'ChecksumMode': 'ENABLED'}
    if journal.get('job_version_id'):
        params['VersionId'] = journal['job_version_id']
    response = s3.get_object(**params)
    body = response.get('Body')
    try:
        size = response.get('ContentLength')
        if body is None or type(size) is not int or not 0 < size <= MAX_JOB:
            raise StateError('published job has invalid size')
        raw = body.read(MAX_JOB + 1)
        pin = PinnedJobVersion(response.get('VersionId'), digest(raw))
        if (len(raw) != size or pin.sha256 != journal['job_sha256'] or
                response.get('ChecksumSHA256') != base64.b64encode(hashlib.sha256(raw).digest()).decode() or
                (journal.get('job_version_id') and journal['job_version_id'] != pin.version_id)):
            raise StateError('published job does not match the exact attempted bytes')
    finally:
        if body is not None:
            body.close()
    journal.update(status='JOB_PUBLISHED_NOT_ACTIVATED', job_version_id=pin.version_id)
    Path(journal_path).write_text(json.dumps(journal, sort_keys=True, indent=2) + '\n')
    return journal


def main():
    if not ((len(sys.argv) == 6 and sys.argv[1] in {'verify', 'publish'}) or
            (len(sys.argv) == 3 and sys.argv[1] == 'reconcile')):
        raise SystemExit('use verify|publish BINDING PLAN RECEIPT_VERSIONS OUT | reconcile ATTEMPT')
    import boto3
    from botocore.config import Config
    session = boto3.Session(region_name=REGION)
    config = Config(connect_timeout=5, read_timeout=10,
                    retries={'total_max_attempts': 1, 'mode': 'standard'})
    if session.client('sts', config=config).get_caller_identity()['Account'] != ACCOUNT:
        raise StateError('wrong AWS account')
    s3 = s3_client(session)
    if sys.argv[1] == 'reconcile':
        result = reconcile(sys.argv[2], s3=s3)
    else:
        binding, document, versions = [json.loads(Path(path).read_text(), object_pairs_hook=_unique)
                                      for path in sys.argv[2:5]]
        now, commit = datetime.now(timezone.utc), source()
        database = session.client('dynamodb', config=config)
        raw, proof = verified_job(binding, document, versions, commit=commit, now=now,
            s3=s3, states=DynamoDBStateStore('tims-software-factory-state', database), database=database)
        if sys.argv[1] == 'publish':
            now = datetime.now(timezone.utc)
            validate_plan(document, document['plan_digest'], commit, now=now)
            result = publish(raw, binding, proof, sys.argv[5], now=now, s3=s3)
            # Confirm the bytes actually stored under the returned version.
            result = reconcile(sys.argv[5], s3=s3)
        else:
            result = {'status': 'SIGNED_JOB_VERIFIED_NOT_PUBLISHED', **proof,
                      'source_commit': commit, 'model_calls': 0, 'activation_authorized': False}
            with Path(sys.argv[5]).open('x', encoding='utf-8') as output:
                output.write(json.dumps(result, sort_keys=True, indent=2) + '\n')
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    main()
