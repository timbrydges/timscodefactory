import base64
import json
import sys
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))

from factory_runtime.intake import IntakePlan
from factory_runtime.receipt_transport import (BUCKET, VersionedS3ReceiptPublisher,
                                               receipt_plan_digest)
from factory_state.dispatch import DispatchRequest, DynamoDBDispatchStore
from factory_state.model import Lease, StateError

NOW = datetime(2026, 9, 23, 0, tzinfo=timezone.utc)


def plan():
    lease = Lease('auto-' + '1' * 24, 'engineering_agent',
                  'engineering_agent_service', NOW + timedelta(minutes=15))
    request = DispatchRequest(lease.lease_id, 'autonomy', 'publication', 'a' * 40,
                              'sha256:' + 'b' * 64, 'sha256:' + 'c' * 64)
    times = {'issued_at': int(NOW.timestamp()),
             'expires_at': int(NOW.timestamp()) + 600}
    capability = {'kind': 'capability', 'factory_id': 'factory',
        'objective_id': 'autonomy', 'capability_id': 'publication',
        'contract_digest': request.contract_digest, 'owner_identity': 'tim_brydges',
        'required_evidence': 'signed result', 'stop_condition': 'one gate', **times}
    review = {'kind': 'scope_review', 'factory_id': 'factory', 'task_id': 'task-1',
        'binding': DynamoDBDispatchStore._binding(request), 'verdict': 'ACCEPTED',
        'reviewer_identity': 'independent_inspector_service',
        'rationale': 'reviewed', **times}
    return IntakePlan('factory', 'task-1', 'IMPLEMENTATION', 4, lease, request,
                      capability, review)


class FakeConfig:
    retries = {'total_max_attempts': 1}


class FakeMeta:
    endpoint_url = 'https://s3.ca-central-1.amazonaws.com'
    config = FakeConfig()


class FakeS3:
    meta = FakeMeta()

    def __init__(self, version='owner-version-1'):
        self.version = version
        self.calls = []

    def put_object(self, **request):
        self.calls.append(request)
        return {'VersionId': self.version}


class Signer:
    def __init__(self, identity, signature=b's' * 64):
        self.identity = identity
        self.signature = signature
        self.calls = []

    def sign(self, payload, *, now):
        self.calls.append((payload, now))
        return self.signature


class ReceiptPublicationTests(unittest.TestCase):
    def test_owner_publication_is_canonical_checksum_bound_and_versioned(self):
        current = plan()
        client = FakeS3()
        signer = Signer('tim_brydges')
        result = VersionedS3ReceiptPublisher(
            client, signer, kind='owner').publish(current, now=NOW)
        digest = receipt_plan_digest(current)
        self.assertEqual(result.plan_digest, digest)
        self.assertEqual(result.version_id, 'owner-version-1')
        self.assertEqual(len(client.calls), 1)
        request = client.calls[0]
        self.assertEqual(request['Bucket'], BUCKET)
        self.assertEqual(request['Key'],
            f'factory-scope-receipts/{digest[7:]}/owner.json')
        self.assertEqual(request['IfNoneMatch'], '*')
        self.assertEqual(request['ServerSideEncryption'], 'AES256')
        self.assertEqual(request['Metadata']['plan-digest'], digest)
        self.assertEqual(request['ChecksumSHA256'], result.checksum_sha256)
        envelope = json.loads(request['Body'])
        self.assertEqual(envelope['payload'], current.capability_payload)
        self.assertEqual(base64.b64decode(envelope['signature_base64']), b's' * 64)
        self.assertEqual(signer.calls, [(current.capability_payload, NOW)])

    def test_independent_reviewer_can_publish_only_review_payload(self):
        current = plan()
        client = FakeS3('review-version-1')
        signer = Signer('independent_inspector_service', b'r' * 64)
        result = VersionedS3ReceiptPublisher(
            client, signer, kind='reviewer').publish(current, now=NOW)
        self.assertTrue(result.key.endswith('/reviewer.json'))
        envelope = json.loads(client.calls[0]['Body'])
        self.assertEqual(envelope['payload'], current.review_payload)
        self.assertEqual(signer.calls, [(current.review_payload, NOW)])

    def test_wrong_signer_invalid_signature_and_unversioned_write_fail_closed(self):
        cases = ((Signer('engineering_agent_service'), FakeS3(), 'signer'),
                 (Signer('tim_brydges', b'short'), FakeS3(), 'signature'),
                 (Signer('tim_brydges'), FakeS3(None), 'version'))
        for signer, client, message in cases:
            with self.subTest(message=message):
                with self.assertRaisesRegex(StateError, message):
                    VersionedS3ReceiptPublisher(
                        client, signer, kind='owner').publish(plan(), now=NOW)

    def test_retry_enabled_client_and_dynamic_destination_are_rejected(self):
        client = FakeS3()
        client.meta = FakeMeta()
        client.meta.config = FakeConfig()
        client.meta.config.retries = {'total_max_attempts': 2}
        with self.assertRaisesRegex(StateError, 'retries disabled'):
            VersionedS3ReceiptPublisher(client, Signer('tim_brydges'), kind='owner')
        with self.assertRaisesRegex(StateError, 'destination'):
            VersionedS3ReceiptPublisher(FakeS3(), Signer('tim_brydges'),
                                        kind='owner', bucket='other')


if __name__ == '__main__':
    unittest.main()
