import base64
import hashlib
import io
import json
import sys
import tempfile
import unittest
from dataclasses import replace
from datetime import timedelta
from pathlib import Path
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / 'src'), str(ROOT / 'scripts'), str(ROOT / 'tests')]

from factory_state.model import CONTROLLER_IDENTITY, StateError, TaskState
from prepare_acceptance_job import BINDING_FIELDS, PLAN_FIELDS
import publish_acceptance_job as publication
from scope_dispatch_canary import fixture_keys, sign
import test_prepare_acceptance_activation_bundle as fixtures
from test_receipt_transport import FakeS3


class Objects(FakeS3):
    def __init__(self, documents):
        super().__init__(documents)
        self.writes = []
        self.job = None
        self.lose_write_response = False

    def put_object(self, **request):
        self.writes.append(request)
        self.job = request['Body']
        if self.lose_write_response:
            raise TimeoutError('response lost after object was stored')
        return {'VersionId': 'job-v1'}

    def get_object(self, **request):
        if request['Key'].startswith('factory-scope-receipts/'):
            return super().get_object(**request)
        self.calls.append(request)
        return {'VersionId': 'job-v1', 'ContentLength': len(self.job),
            'ChecksumSHA256': base64.b64encode(hashlib.sha256(self.job).digest()).decode(),
            'Body': io.BytesIO(self.job)}


class JobPublicationTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.directory = Path(directory.name)
        self.keys, private = fixture_keys(directory.name)
        binding, raw, self.now = fixtures.ActivationBundleTests().material()
        job = json.loads(raw)
        self.binding = {key: binding[key] for key in BINDING_FIELDS}
        self.document = {key: job[key] for key in PLAN_FIELDS}
        self.versions = job['receipt_versions']
        prefix = 'factory-scope-receipts/' + job['plan_digest'][7:]
        documents = {}
        for kind, identity, payload in (
            ('owner', 'tim_brydges', job['capability_payload']),
            ('reviewer', 'independent_inspector_service', job['review_payload'])):
            envelope = {'schema_version': '1.0', 'plan_digest': job['plan_digest'],
                'signer_identity': identity, 'payload': payload,
                'signature_base64': base64.b64encode(sign(payload, private[identity], directory.name)).decode()}
            documents[(prefix + '/' + kind + '.json', self.versions[kind])] = json.dumps(envelope).encode()
        self.s3 = Objects(documents)
        self.state = TaskState(job['factory_id'], job['task_id'], 'IMPLEMENTATION',
                               job['state_version'], self.now, CONTROLLER_IDENTITY)
        self.states = Mock()
        self.states.load_state.return_value = self.state
        self.database = Mock()
        self.database.get_item.return_value = {}
        self.loader = patch.object(publication, 'load_trusted_signers', return_value=self.keys)
        self.loader.start()
        self.addCleanup(self.loader.stop)

    def verify(self, **changes):
        return publication.verified_job(self.binding, self.document, self.versions,
            **{'commit': self.binding['source_commit'], 'now': self.now, 's3': self.s3,
               'states': self.states, 'database': self.database, **changes})

    def test_real_signatures_and_current_state_allow_one_immutable_job(self):
        raw, proof = self.verify()
        self.assertEqual(len(self.s3.calls), 2)
        journal = self.directory / 'attempt.json'
        result = publication.publish(raw, self.binding, proof, journal, now=self.now, s3=self.s3)
        result = publication.reconcile(journal, s3=self.s3)
        self.assertEqual(result['status'], 'JOB_PUBLISHED_NOT_ACTIVATED')
        self.assertFalse(result['activation_authorized'])
        self.assertEqual(result['job_version_id'], 'job-v1')
        self.assertEqual(len(self.s3.writes), 1)
        self.assertEqual(self.s3.writes[0]['IfNoneMatch'], '*')
        self.assertEqual(self.s3.writes[0]['ServerSideEncryption'], 'AES256')
        self.database.get_item.assert_called_once_with(TableName='tims-factory-acceptance-budget',
            Key={'PK': {'S': 'ACTIVATION#' + self.binding['activation_id']}, 'SK': {'S': 'BUDGET'}},
            ConsistentRead=True)

    def test_forged_signature_is_rejected_without_upload(self):
        key = next(iter(self.s3.documents))
        envelope = json.loads(self.s3.documents[key])
        envelope['signature_base64'] = base64.b64encode(b'x' * 64).decode()
        self.s3.documents[key] = json.dumps(envelope).encode()
        with self.assertRaises(StateError):
            self.verify()
        self.assertEqual(self.s3.writes, [])

    def test_stale_state_spent_budget_source_drift_and_expiry_deny_before_receipt_io(self):
        for state in (None, replace(self.state, version=self.state.version + 1)):
            self.states.load_state.return_value = state
            with self.assertRaisesRegex(StateError, 'authoritative task'):
                self.verify()
        self.states.load_state.return_value = self.state
        self.database.get_item.return_value = {'Item': {'calls': {'N': '1'}}}
        with self.assertRaisesRegex(StateError, 'already present'):
            self.verify()
        self.database.get_item.return_value = {}
        with self.assertRaises(StateError):
            self.verify(commit='b' * 40)
        with self.assertRaises(StateError):
            self.verify(now=self.now + timedelta(hours=1))
        self.assertEqual(self.s3.calls, [])
        self.assertEqual(self.s3.writes, [])

    def test_lost_write_response_is_reconciled_without_second_write(self):
        raw, proof = self.verify()
        self.s3.lose_write_response = True
        journal = self.directory / 'attempt.json'
        with self.assertRaises(TimeoutError):
            publication.publish(raw, self.binding, proof, journal, now=self.now, s3=self.s3)
        self.assertEqual(json.loads(journal.read_text())['status'], 'ATTEMPTED_RECONCILE_REQUIRED')
        with self.assertRaises(FileExistsError):
            publication.publish(raw, self.binding, proof, journal, now=self.now, s3=self.s3)
        result = publication.reconcile(journal, s3=self.s3)
        self.assertEqual(result['job_version_id'], 'job-v1')
        self.assertEqual(len(self.s3.writes), 1)

    def test_reconciliation_rejects_changed_object_even_with_valid_checksum(self):
        raw, proof = self.verify()
        journal = self.directory / 'attempt.json'
        publication.publish(raw, self.binding, proof, journal, now=self.now, s3=self.s3)
        self.s3.job += b' '
        with self.assertRaisesRegex(StateError, 'exact attempted bytes'):
            publication.reconcile(journal, s3=self.s3)
        self.assertEqual(len(self.s3.writes), 1)


if __name__ == '__main__':
    unittest.main()
