import json
import sys
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))

from factory_runtime.inspector_budget import InspectorBudgetStore, PROFILE
from factory_runtime.inspector_runtime import (
    InspectorReviewRuntime, validate_authenticated_decision)
from factory_runtime.intake import IntakePlan
from factory_runtime.receipt_transport import (
    VersionedS3ReceiptPublisher, receipt_plan_digest)
from factory_state.dispatch import DispatchRequest, DynamoDBDispatchStore
from factory_state.model import Lease, StateError

NOW = datetime(2026, 9, 30, 8, 0, tzinfo=timezone.utc)


class Config:
    retries = {'total_max_attempts': 1}


class BedrockMeta:
    endpoint_url = 'https://bedrock-runtime.ca-central-1.amazonaws.com'
    config = Config()


class Bedrock:
    meta = BedrockMeta()

    def __init__(self, response=None, error=None, calls=None):
        self.response = response
        self.error = error
        self.calls = calls if calls is not None else []

    def converse(self, **request):
        self.calls.append(('bedrock', request))
        if self.error:
            raise self.error
        return self.response


class Table:
    def __init__(self, calls=None):
        self.items = {}
        self.calls = calls if calls is not None else []

    def put_item(self, *, TableName, Item, ConditionExpression):
        self.calls.append(('budget', Item['PK']['S']))
        key = (Item['PK']['S'], Item['SK']['S'])
        if key in self.items:
            raise RuntimeError('conditional write failed')
        self.items[key] = Item


class S3Config:
    retries = {'total_max_attempts': 1}


class S3Meta:
    endpoint_url = 'https://s3.ca-central-1.amazonaws.com'
    config = S3Config()


class S3:
    meta = S3Meta()

    def __init__(self):
        self.calls = []

    def put_object(self, **request):
        self.calls.append(request)
        return {'VersionId': 'review-version-1'}


class Signer:
    identity = 'independent_inspector_service'

    def __init__(self):
        self.calls = []

    def sign(self, payload, *, now):
        self.calls.append((payload, now))
        return b'r' * 64


def fixture():
    lease = Lease('auto-' + '1'*24, 'engineering_agent',
                  'engineering_agent_service', NOW + timedelta(minutes=15))
    request = DispatchRequest(
        lease.lease_id, 'autonomy', 'publication', 'a'*40,
        'sha256:' + 'b'*64, 'sha256:' + 'c'*64)
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
    plan = IntakePlan('factory', 'task-1', 'IMPLEMENTATION', 4, lease, request,
                      capability, review)
    digest = receipt_plan_digest(plan)
    material = {'activation_id': 'acceptance-001', 'plan_digest': digest,
                'input_digest': request.input_digest,
                'contract_digest': request.contract_digest}
    prepared = {'status': 'PREPARED_NOT_INVOKED',
                'model_calls_authorized': 0, 'plan_digest': digest,
                'system': 'Review the exact bounded task and return JSON only.',
                'user': json.dumps(material, sort_keys=True)}
    return plan, prepared


def provider_response(request, verdict='ACCEPTED'):
    material = json.loads(request['user'])
    body = {'verdict': verdict, 'rationale': 'exact bounded task reviewed',
            'evidence': ['digests and scope match']}
    return {'output': {'message': {'content': [{'toolUse': {
                'toolUseId': 'assessment-1',
                'name': 'submit_inspector_assessment',
                'input': body}}]}},
            'stopReason': 'tool_use',
            'usage': {'inputTokens': 200, 'outputTokens': 50, 'totalTokens': 250}}


class InspectorRuntimeTests(unittest.TestCase):
    def setUp(self):
        self.policy = json.loads((ROOT/'factory/evidence/acceptance-inspector-sonnet45-budget-policy-2026-09-30.json').read_text())

    def test_reserves_before_single_call_and_authenticates_accepted_decision(self):
        plan, request = fixture()
        calls = []
        table = Table(calls)
        bedrock = Bedrock(provider_response(request), calls=calls)
        runtime = InspectorReviewRuntime(
            bedrock, InspectorBudgetStore('tims-factory-acceptance-budget', table))
        decision = runtime.review(request=request, plan=plan,
                                  policy=self.policy, now=NOW)
        self.assertEqual([item[0] for item in calls], ['budget', 'bedrock'])
        provider_request = next(item[1] for item in calls if item[0] == 'bedrock')
        self.assertEqual(
            provider_request['toolConfig']['toolChoice'],
            {'tool': {'name': 'submit_inspector_assessment'}})
        self.assertEqual(
            provider_request['toolConfig']['tools'][0]['toolSpec']['name'],
            'submit_inspector_assessment')
        schema = provider_request['toolConfig']['tools'][0]['toolSpec']['inputSchema']['json']
        self.assertEqual(set(schema['required']), {'verdict', 'rationale', 'evidence'})
        self.assertNotIn('plan_digest', schema['properties'])
        schema = provider_request['toolConfig']['tools'][0]['toolSpec']['inputSchema']['json']
        self.assertEqual(set(schema['required']), {'verdict', 'rationale', 'evidence'})
        self.assertNotIn('plan_digest', schema['properties'])
        self.assertEqual(decision.verdict, 'ACCEPTED')
        self.assertEqual(decision.model_id, PROFILE)
        self.assertEqual(decision.actual_cost_usd, '0.00135')
        self.assertIs(validate_authenticated_decision(decision, plan), decision)

        client, signer = S3(), Signer()
        publication = VersionedS3ReceiptPublisher(
            client, signer, kind='reviewer').publish(
                plan, now=NOW, inspector_decision=decision)
        self.assertEqual(publication.version_id, 'review-version-1')
        self.assertEqual(signer.calls, [(plan.review_payload, NOW)])

    def test_rejected_or_forged_decision_cannot_publish(self):
        plan, request = fixture()
        table = Table()
        runtime = InspectorReviewRuntime(
            Bedrock(provider_response(request, 'REJECTED')),
            InspectorBudgetStore('tims-factory-acceptance-budget', table))
        decision = runtime.review(request=request, plan=plan,
                                  policy=self.policy, now=NOW)
        self.assertEqual(decision.verdict, 'REJECTED')
        with self.assertRaisesRegex(StateError, 'differs from reviewed plan'):
            VersionedS3ReceiptPublisher(S3(), Signer(), kind='reviewer').publish(
                plan, now=NOW, inspector_decision=decision)
        with self.assertRaisesRegex(StateError, 'authenticated Inspector'):
            VersionedS3ReceiptPublisher(S3(), Signer(), kind='reviewer').publish(
                plan, now=NOW, inspector_decision=SimpleNamespace(
                    verdict='ACCEPTED', plan_digest=receipt_plan_digest(plan)))

    def test_tool_cannot_override_runtime_bound_digests(self):
        plan, request = fixture()
        table = Table()
        response = provider_response(request)
        response['output']['message']['content'][0]['toolUse']['input']['plan_digest'] = (
            'sha256:' + '0' * 64)
        runtime = InspectorReviewRuntime(
            Bedrock(response),
            InspectorBudgetStore('tims-factory-acceptance-budget', table))
        with self.assertRaisesRegex(StateError, 'provider response or usage is malformed'):
            runtime.review(request=request, plan=plan, policy=self.policy, now=NOW)

    def test_free_text_assessment_is_rejected_after_reservation(self):
        plan, request = fixture()
        table = Table()
        bad = {'output': {'message': {'content': [{'text': '{"verdict":"ACCEPTED"}'}]}},
               'stopReason': 'end_turn',
               'usage': {'inputTokens': 200, 'outputTokens': 20, 'totalTokens': 220}}
        bedrock = Bedrock(bad)
        runtime = InspectorReviewRuntime(
            bedrock, InspectorBudgetStore('tims-factory-acceptance-budget', table))
        with self.assertRaisesRegex(StateError, 'provider response or usage is malformed'):
            runtime.review(request=request, plan=plan, policy=self.policy, now=NOW)
        self.assertEqual(len(bedrock.calls), 1)
        with self.assertRaisesRegex(StateError, 'already reserved'):
            runtime.review(request=request, plan=plan, policy=self.policy, now=NOW)
        self.assertEqual(len(bedrock.calls), 1)

    def test_provider_failure_consumes_reservation_and_cannot_retry(self):
        plan, request = fixture()
        table = Table()
        calls = []
        bedrock = Bedrock(error=RuntimeError('unknown outcome'), calls=calls)
        runtime = InspectorReviewRuntime(
            bedrock, InspectorBudgetStore('tims-factory-acceptance-budget', table))
        with self.assertRaisesRegex(RuntimeError, 'unknown outcome'):
            runtime.review(request=request, plan=plan, policy=self.policy, now=NOW)
        self.assertEqual(len(calls), 1)
        with self.assertRaisesRegex(StateError, 'already reserved'):
            runtime.review(request=request, plan=plan, policy=self.policy, now=NOW)
        self.assertEqual(len(calls), 1)


if __name__ == '__main__':
    unittest.main()
