import json
import sys
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))

from factory_runtime.lambda_role import (
    INSPECTOR_AUTHORIZATION_ID,
    INSPECTOR_CONTRACT_DIGEST,
    INSPECTOR_INPUT_DIGEST,
    handle_inspector_live_review,
)
from factory_runtime.intake import IntakePlan
from factory_runtime.receipt_transport import receipt_plan_digest
from factory_state.dispatch import DispatchRequest, DynamoDBDispatchStore
from factory_state.model import Lease, StateError

NOW = datetime(2026, 9, 30, 5, 0, tzinfo=timezone.utc)
COMMIT = 'a' * 40


class Config:
    retries = {'total_max_attempts': 1}


class BedrockMeta:
    endpoint_url = 'https://bedrock-runtime.ca-central-1.amazonaws.com'
    config = Config()


class Bedrock:
    meta = BedrockMeta()

    def __init__(self):
        self.calls = []

    def converse(self, **request):
        self.calls.append(request)
        material = json.loads(request['messages'][0]['content'][0]['text'])
        response = {
            'plan_digest': material['plan_digest'],
            'input_digest': material['input_digest'],
            'contract_digest': material['contract_digest'],
            'verdict': 'ACCEPTED',
            'rationale': 'Exact bounded acceptance scope is consistent.',
            'evidence': ['contract digest matches', 'input digest matches'],
        }
        return {
            'output': {'message': {'content': [{'text': json.dumps(response)}]}},
            'usage': {'inputTokens': 300, 'outputTokens': 60, 'totalTokens': 360},
        }


class BudgetTable:
    def __init__(self):
        self.items = {}

    def put_item(self, *, TableName, Item, ConditionExpression):
        key = (Item['PK']['S'], Item['SK']['S'])
        if key in self.items:
            raise RuntimeError('conditional write failed')
        self.items[key] = Item


class S3:
    meta = SimpleNamespace(
        endpoint_url='https://s3.ca-central-1.amazonaws.com',
        config=SimpleNamespace(retries={'total_max_attempts': 1}))

    def __init__(self):
        self.calls = []

    def put_object(self, **request):
        self.calls.append(request)
        return {'VersionId': 'review-version-live-1'}


class Session:
    def __init__(self, s3):
        self.s3 = s3

    def client(self, service, **kwargs):
        if service != 's3':
            raise AssertionError(service)
        return self.s3


class Signer:
    identity = 'independent_inspector_service'

    def __init__(self):
        self.calls = []

    def sign(self, payload, *, now):
        self.calls.append((payload, now))
        return b'r' * 64


def fixture():
    lease = Lease('auto-' + '1' * 24, 'engineering_agent',
                  'engineering_agent_service', NOW + timedelta(minutes=45))
    request = DispatchRequest(
        lease.lease_id, 'autonomy', 'acceptance', COMMIT,
        INSPECTOR_CONTRACT_DIGEST, INSPECTOR_INPUT_DIGEST)
    times = {'issued_at': int(NOW.timestamp()) - 30,
             'expires_at': int(NOW.timestamp()) + 1200}
    capability = {
        'kind': 'capability', 'factory_id': 'tims-software-factory',
        'objective_id': 'autonomy', 'capability_id': 'acceptance',
        'contract_digest': INSPECTOR_CONTRACT_DIGEST,
        'owner_identity': 'tim_brydges',
        'required_evidence': 'exact acceptance scope',
        'stop_condition': 'one Inspector call',
        **times,
    }
    review = {
        'kind': 'scope_review', 'factory_id': 'tims-software-factory',
        'task_id': 'deterministic-text-fingerprint',
        'binding': DynamoDBDispatchStore._binding(request),
        'verdict': 'ACCEPTED',
        'reviewer_identity': 'independent_inspector_service',
        'rationale': 'independent review required',
        **times,
    }
    plan = IntakePlan(
        'tims-software-factory', 'deterministic-text-fingerprint',
        'IMPLEMENTATION', 3, lease, request, capability, review)
    plan_document = {
        'factory_id': plan.factory_id,
        'task_id': plan.task_id,
        'state': plan.state,
        'state_version': plan.state_version,
        'lease': {
            'lease_id': lease.lease_id,
            'role_id': lease.role_id,
            'authoritative_identity': lease.authoritative_identity,
            'expires_at': lease.expires_at.isoformat(),
            'revoked': lease.revoked,
        },
        'request': {
            'lease_id': request.lease_id,
            'objective_id': request.objective_id,
            'capability_id': request.capability_id,
            'source_commit': request.source_commit,
            'contract_digest': request.contract_digest,
            'input_digest': request.input_digest,
        },
        'capability_payload': capability,
        'review_payload': review,
        'plan_digest': receipt_plan_digest(plan),
    }
    material = {
        'activation_id': 'inspector-review-2026-09-30-003',
        'plan_digest': plan_document['plan_digest'],
        'input_digest': INSPECTOR_INPUT_DIGEST,
        'contract_digest': INSPECTOR_CONTRACT_DIGEST,
    }
    prepared = {
        'status': 'PREPARED_NOT_INVOKED',
        'provider_profile': 'review_adversarial',
        'plan_digest': plan_document['plan_digest'],
        'model_calls_authorized': 0,
        'system': 'Review the exact bounded acceptance scope and return only JSON.',
        'user': json.dumps(material, sort_keys=True),
    }
    event = {
        'kind': 'inspector_live_review',
        'source_commit': COMMIT,
        'task_id': 'deterministic-text-fingerprint',
        'authorization_id': INSPECTOR_AUTHORIZATION_ID,
        'plan': plan_document,
        'request': prepared,
    }
    return event


class LiveInspectorReviewTests(unittest.TestCase):
    def test_exact_authorized_review_reserves_calls_once_and_publishes_receipt(self):
        event = fixture()
        table, bedrock, s3, signer = BudgetTable(), Bedrock(), S3(), Signer()
        with patch('factory_runtime.receipt_transport.s3_client', return_value=s3):
            result = handle_inspector_live_review(
                event, role='inspector', commit=COMMIT, signer=signer,
                now=NOW, root=ROOT, session=Session(s3), database=table,
                bedrock=bedrock)
        self.assertEqual(result['status'],
                         'INSPECTOR_REVIEW_ACCEPTED_AND_RECEIPT_PUBLISHED')
        self.assertEqual(result['model_calls'], 1)
        self.assertEqual(result['provider_calls_remaining'], 0)
        self.assertEqual(result['reviewer_receipt_version'], 'review-version-live-1')
        self.assertEqual(len(bedrock.calls), 1)
        self.assertEqual(len(s3.calls), 1)
        with self.assertRaisesRegex(StateError, 'already reserved'):
            handle_inspector_live_review(
                event, role='inspector', commit=COMMIT, signer=signer,
                now=NOW, root=ROOT, session=Session(s3), database=table,
                bedrock=bedrock)
        self.assertEqual(len(bedrock.calls), 1)

    def test_changed_binding_fails_before_provider_call(self):
        event = fixture()
        event['plan']['request']['input_digest'] = 'sha256:' + '0' * 64
        bedrock = Bedrock()
        with self.assertRaisesRegex(StateError, 'owner-authorized task'):
            handle_inspector_live_review(
                event, role='inspector', commit=COMMIT, signer=Signer(),
                now=NOW, root=ROOT, session=Session(S3()), database=BudgetTable(),
                bedrock=bedrock)
        self.assertEqual(bedrock.calls, [])


if __name__ == '__main__':
    unittest.main()
