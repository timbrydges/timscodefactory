"""Prepare matching controller configuration and IAM from one reviewed job file.

Offline preparation only: the supplied bytes and S3 version must subsequently be
matched against the actual versioned object before any policy is attached.
"""
from __future__ import annotations

import base64
import hashlib
import io
import json
import sys
from datetime import datetime
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))

from factory_runtime.acceptance_jobs import (MAX_JOB, PinnedJobVersion,
                                             VersionedS3AcceptanceJobSource)
from factory_runtime.autonomy import AutonomyActivation
from factory_runtime.cloud_roles import FUNCTION
from factory_runtime.receipt_transport import receipt_plan_digest
from factory_state.model import COMMIT_SHA, SHA256_DIGEST, CONTROLLER_IDENTITY, TaskState

from prepare_acceptance_controller_iam import build_policy


class _LocalVersionedObject:
    """Supply reviewed local bytes to the runtime's actual job decoder."""
    def __init__(self, raw: bytes, version: str):
        self.raw, self.version = raw, version
        self.meta = SimpleNamespace(config=SimpleNamespace(retries={'total_max_attempts': 1}),
            endpoint_url='https://s3.ca-central-1.amazonaws.com')

    def get_object(self, **kwargs):
        if kwargs != {'Bucket': 'tims-software-factory-666730517561-ca-central-1',
                'Key': f'factory-autonomy-jobs/{self.activation_id}/IMPLEMENTATION.json',
                'VersionId': self.version, 'ChecksumMode': 'ENABLED'}:
            raise ValueError('job read differs from reviewed location')
        return {'VersionId': self.version, 'ContentLength': len(self.raw),
                'ChecksumSHA256': base64.b64encode(hashlib.sha256(self.raw).digest()).decode(),
                'Body': io.BytesIO(self.raw)}


def build_bundle(binding: dict, raw: bytes) -> dict:
    fields = {'activation_id', 'source_commit', 'contract_digest', 'starts_at',
              'expires_at', 'builder_version_arn', 'job_version_id'}
    if not isinstance(binding, dict) or set(binding) != fields:
        raise ValueError('controller binding has missing or extra fields')
    if (not isinstance(raw, bytes) or not 0 < len(raw) <= MAX_JOB or
            not isinstance(binding['source_commit'], str) or
            not COMMIT_SHA.fullmatch(binding['source_commit']) or
            not isinstance(binding['contract_digest'], str) or
            not SHA256_DIGEST.fullmatch(binding['contract_digest']) or
            not isinstance(binding['builder_version_arn'], str) or
            not (match := FUNCTION.fullmatch(binding['builder_version_arn'])) or
            match.group(1) != 'builder'):
        raise ValueError('invalid reviewed controller source, contract, role, or job')
    try:
        starts = datetime.fromisoformat(binding['starts_at'])
        expires = datetime.fromisoformat(binding['expires_at'])
    except (TypeError, ValueError) as error:
        raise ValueError('invalid activation window') from error
    activation = AutonomyActivation(binding['activation_id'], 'tims-software-factory',
        'deterministic-text-fingerprint', binding['source_commit'],
        binding['contract_digest'], starts, expires)
    activation.validate(starts)
    pin = PinnedJobVersion(binding['job_version_id'],
        'sha256:' + hashlib.sha256(raw).hexdigest())
    object_reader = _LocalVersionedObject(raw, pin.version_id)
    object_reader.activation_id = activation.activation_id
    source = VersionedS3AcceptanceJobSource(object_reader, activation,
        {'IMPLEMENTATION': pin})
    # The job's state version is checked by the runtime decoder. A separate
    # deployment canary must compare it with the actual durable state.
    try:
        document = json.loads(raw)
        state_version = document['state_version']
    except (TypeError, ValueError, KeyError) as error:
        raise ValueError('invalid reviewed job document') from error
    state = TaskState(activation.factory_id, activation.task_id,
        'IMPLEMENTATION', state_version, starts, CONTROLLER_IDENTITY)
    job = source.load(activation.factory_id, activation.task_id, state)
    digest = receipt_plan_digest(job.plan)
    iam_binding = {'activation_id': activation.activation_id,
        'builder_version_arn': binding['builder_version_arn'],
        'job_version_id': pin.version_id, 'receipt_plan_digest': digest,
        'owner_receipt_version_id': job.receipt_versions.owner,
        'reviewer_receipt_version_id': job.receipt_versions.reviewer}
    config = {'activation_id': activation.activation_id, 'factory_id': activation.factory_id,
        'task_id': activation.task_id, 'source_commit': activation.source_commit,
        'contract_digest': activation.contract_digest,
        'starts_at': starts.isoformat(), 'expires_at': expires.isoformat(),
        'builder_version_arn': binding['builder_version_arn'],
        'job_versions': {'IMPLEMENTATION': {'version_id': pin.version_id,
                                            'sha256': pin.sha256}}}
    return {'status': 'PREPARED_NOT_DEPLOYED', 'controller_config': config,
            'policy': build_policy(iam_binding), 'job_object_sha256': pin.sha256,
            'receipt_plan_digest': digest, 'model_calls_authorized': 0}


def main():
    if len(sys.argv) != 4:
        raise SystemExit('usage: prepare_acceptance_controller_bundle.py BINDING.json JOB.json OUT.json')
    result = build_bundle(json.loads(Path(sys.argv[1]).read_text()),
                          Path(sys.argv[2]).read_bytes())
    Path(sys.argv[3]).write_text(json.dumps(result, sort_keys=True, indent=2) + '\n')


if __name__ == '__main__':
    main()
