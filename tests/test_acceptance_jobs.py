import base64
import hashlib
import io
import json
import sys
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))

from factory_runtime.acceptance_jobs import (
    PinnedJobVersion, VersionedS3AcceptanceJobSource, encode_job,
)
from factory_runtime.autonomy import AutonomyActivation, ScheduledAutonomyJob
from factory_runtime.intake import IntakePlan
from factory_runtime.receipt_transport import BUCKET, ReceiptVersions
from factory_runtime.worker import digest
from factory_state.dispatch import DispatchRequest
from factory_state.model import CONTROLLER_IDENTITY, Lease, StateError, TaskState

NOW = datetime(2026, 9, 29, 6, tzinfo=timezone.utc)
COMMIT = 'a' * 40
INPUT = b'deterministic fingerprint input'
CONTRACT = b'approved contract'


class S3:
    def __init__(self, raw, *, version='version-1'):
        self.raw, self.version = raw, version
        self.calls = []
        self.meta = SimpleNamespace(
            config=SimpleNamespace(retries={'total_max_attempts': 1}),
            endpoint_url='https://s3.ca-central-1.amazonaws.com')

    def get_object(self, **kwargs):
        self.calls.append(kwargs)
        return {'VersionId': self.version, 'ContentLength': len(self.raw),
                'ChecksumSHA256': base64.b64encode(hashlib.sha256(self.raw).digest()).decode(),
                'Body': io.BytesIO(self.raw)}


def material():
    activation = AutonomyActivation('acceptance-1', 'tims-software-factory',
        'deterministic-text-fingerprint', COMMIT, digest(CONTRACT),
        NOW - timedelta(minutes=1), NOW + timedelta(hours=1))
    lease = Lease('auto-' + '2' * 24, 'engineering_agent',
        'engineering_agent_service', NOW + timedelta(minutes=15))
    request = DispatchRequest(lease.lease_id, 'autonomy', 'acceptance', COMMIT,
        digest(CONTRACT), digest(INPUT))
    plan = IntakePlan(activation.factory_id, activation.task_id, 'IMPLEMENTATION',
        3, lease, request, {'kind': 'capability'}, {'kind': 'scope_review'})
    job = ScheduledAutonomyJob(plan, ReceiptVersions('owner-v1', 'review-v1'),
        INPUT, CONTRACT)
    state = TaskState(activation.factory_id, activation.task_id, 'IMPLEMENTATION',
        3, NOW, CONTROLLER_IDENTITY)
    return activation, job, state


class VersionedAcceptanceJobSourceTests(unittest.TestCase):
    def source(self, raw=None, *, client=None):
        activation, job, state = material()
        raw = raw if raw is not None else encode_job(job, activation.activation_id)
        client = client or S3(raw)
        pin = PinnedJobVersion('version-1', digest(raw))
        source = VersionedS3AcceptanceJobSource(
            client, activation, {'IMPLEMENTATION': pin})
        return source, client, job, state

    def test_exact_version_and_digest_restore_reviewed_plan(self):
        source, client, job, state = self.source()
        loaded = source.load(state.factory_id, state.task_id, state)
        self.assertEqual(loaded, job)
        self.assertEqual(client.calls, [{'Bucket': BUCKET,
            'Key': 'factory-autonomy-jobs/acceptance-1/IMPLEMENTATION.json',
            'VersionId': 'version-1', 'ChecksumMode': 'ENABLED'}])
        # After intake issues the lease, the same object remains the source of truth.
        after_lease = TaskState(state.factory_id, state.task_id, state.state,
            4, NOW, CONTROLLER_IDENTITY, leases=(job.plan.lease,))
        self.assertEqual(source.load(state.factory_id, state.task_id, after_lease), job)

    def test_wrong_stage_or_task_denies_without_read(self):
        source, client, _, state = self.source()
        with self.assertRaisesRegex(StateError, 'deployment'):
            source.load(state.factory_id, 'other', state)
        other = TaskState(state.factory_id, state.task_id, 'INSPECTION',
            4, NOW, CONTROLLER_IDENTITY)
        with self.assertRaisesRegex(StateError, 'deployment'):
            source.load(state.factory_id, state.task_id, other)
        self.assertEqual(client.calls, [])

    def test_stale_version_and_changed_bytes_fail_before_plan(self):
        raw = encode_job(material()[1], 'acceptance-1')
        for client in (S3(raw, version='later-version'), S3(raw + b' ')):
            source, _, _, state = self.source(raw, client=client)
            with self.subTest(client=client), self.assertRaises(StateError):
                source.load(state.factory_id, state.task_id, state)

    def test_same_valid_object_checksum_cannot_widen_work_or_receipts(self):
        activation, job, state = material()
        original = json.loads(encode_job(job, activation.activation_id))
        changes = (
            {'activation_id': 'other'},
            {'plan_digest': digest(b'other')},
            {'receipt_versions': {'owner': '', 'reviewer': 'review-v1'}},
            {'input_base64': base64.b64encode(b'changed').decode()},
            {'state_version': True},
        )
        for change in changes:
            raw = json.dumps({**original, **change}).encode()
            source, _, _, _ = self.source(raw)
            with self.subTest(change=change), self.assertRaises(StateError):
                source.load(state.factory_id, state.task_id, state)

    def test_duplicate_fields_and_retry_enabled_client_fail_closed(self):
        activation, job, state = material()
        raw = encode_job(job, activation.activation_id)
        duplicate = raw.replace(b'"schema_version":"1.0"',
            b'"schema_version":"1.0","schema_version":"1.0"')
        source, _, _, _ = self.source(duplicate)
        with self.assertRaisesRegex(StateError, 'duplicate'):
            source.load(state.factory_id, state.task_id, state)
        client = S3(raw)
        client.meta.config.retries['total_max_attempts'] = 2
        with self.assertRaisesRegex(StateError, 'no-retry'):
            VersionedS3AcceptanceJobSource(client, activation,
                {'IMPLEMENTATION': PinnedJobVersion('version-1', digest(raw))})


if __name__ == '__main__':
    unittest.main()
