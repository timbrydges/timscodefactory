import json
import sys
import unittest
from dataclasses import asdict, replace
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / 'scripts'), str(ROOT / 'src'), str(ROOT / 'tests')]

from factory_runtime.acceptance_jobs import encode_job
from factory_runtime.intake import IntakePlan
from factory_runtime.receipt_transport import receipt_plan_digest
from factory_state.dispatch import DynamoDBDispatchStore
from factory_state.model import StateError
from prepare_acceptance_job import prepare
from test_acceptance_jobs import NOW, material


def fixtures():
    activation, job, _ = material()
    times = {'issued_at': int(NOW.timestamp()),
             'expires_at': int(NOW.timestamp()) + 600}
    capability = {'kind': 'capability', 'factory_id': activation.factory_id,
        'objective_id': job.plan.request.objective_id,
        'capability_id': job.plan.request.capability_id,
        'contract_digest': activation.contract_digest, 'owner_identity': 'tim_brydges',
        'required_evidence': 'exact acceptance task', 'stop_condition': 'one bounded run',
        **times}
    review = {'kind': 'scope_review', 'factory_id': activation.factory_id,
        'task_id': activation.task_id,
        'binding': DynamoDBDispatchStore._binding(job.plan.request),
        'verdict': 'ACCEPTED', 'reviewer_identity': 'independent_inspector_service',
        'rationale': 'exact task and bounds reviewed', **times}
    plan = replace(job.plan, capability_payload=capability, review_payload=review)
    document = {**asdict(plan), 'plan_digest': receipt_plan_digest(plan)}
    document['lease']['expires_at'] = plan.lease.expires_at.isoformat()
    binding = {'activation_id': activation.activation_id,
        'source_commit': activation.source_commit,
        'contract_digest': activation.contract_digest,
        'starts_at': activation.starts_at.isoformat(),
        'expires_at': activation.expires_at.isoformat(),
        'builder_version_arn':
            'arn:aws:lambda:ca-central-1:666730517561:function:tims-factory-builder:8'}
    versions = asdict(job.receipt_versions)
    return binding, document, versions, job.input_bytes, job.contract_bytes


class PrepareAcceptanceJobTests(unittest.TestCase):
    def test_prepares_exact_job_without_authorizing_or_publishing(self):
        binding, document, versions, input_bytes, contract_bytes = fixtures()
        raw, result = prepare(binding, document, versions, input_bytes,
                              contract_bytes, now=NOW)
        encoded = json.loads(raw)
        self.assertEqual(encoded['receipt_versions'], versions)
        self.assertEqual(encoded['plan_digest'], document['plan_digest'])
        self.assertEqual(result['status'], 'PREPARED_NOT_PUBLISHED')
        self.assertEqual(result['model_calls_authorized'], 0)

    def test_rejects_changed_digest_identity_versions_and_expiry(self):
        binding, document, versions, input_bytes, contract_bytes = fixtures()
        cases = [
            (binding, {**document, 'plan_digest': 'sha256:' + '0' * 64}, versions,
             input_bytes, contract_bytes, NOW),
            (binding, document, {**versions, 'reviewer': 'null'},
             input_bytes, contract_bytes, NOW),
            (binding, document, versions, input_bytes + b'changed', contract_bytes, NOW),
            (binding, {**document, 'review_payload': {
                **document['review_payload'], 'reviewer_identity': 'tim_brydges'}},
             versions, input_bytes, contract_bytes, NOW),
            (binding, document, versions, input_bytes, contract_bytes,
             NOW.replace(hour=1)),
        ]
        for args in cases:
            with self.subTest(args=args[:3]), self.assertRaises((StateError, ValueError)):
                prepare(*args[:5], now=args[5])


if __name__ == '__main__':
    unittest.main()
