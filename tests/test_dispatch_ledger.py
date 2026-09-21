"""Offline authority and DynamoDB transaction contract tests.

These inspect the real requests, not an emulator of DynamoDB expressions.
Live contention/crash proof is an explicit separate activation milestone.
"""
import sys
import unittest
from copy import deepcopy
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from factory_state.dispatch import DispatchRequest, DynamoDBDispatchStore
from factory_state.dynamodb import DynamoDBStateStore
from factory_state.model import AuthorityError, StateError, LeaseError, Lease, TaskState, CONTROLLER_IDENTITY

NOW = datetime(2026, 9, 21, tzinfo=timezone.utc)
REQUEST = DispatchRequest('lease-1', 'factory-autonomy', 'durable-dispatch', 'a' * 40, 'sha256:' + 'b' * 64, 'sha256:' + 'c' * 64)


class RecordingClient:
    def __init__(self):
        self.calls = []
        self.item = None

    def transact_write_items(self, **kwargs):
        self.calls.append(deepcopy(kwargs))

    def update_item(self, **kwargs):
        self.calls.append(deepcopy(kwargs))

    def get_item(self, **kwargs):
        self.calls.append(deepcopy(kwargs))
        return {'Item': deepcopy(self.item)} if self.item else {}


def snapshot():
    lease = Lease('lease-1', 'engineering_agent', 'engineering_agent_service', NOW + timedelta(minutes=5))
    return TaskState('factory', 'task-1', 'IMPLEMENTATION', 3, NOW, CONTROLLER_IDENTITY, (lease,))


class DispatchLedgerTests(unittest.TestCase):
    def setUp(self):
        self.client = RecordingClient()
        self.store = DynamoDBDispatchStore('state-table', self.client)
        self.state = snapshot()

    def enqueue(self, state=None, request=REQUEST):
        return self.store.enqueue(state or self.state, request, caller_identity=CONTROLLER_IDENTITY, now=NOW)

    def claim(self, state=None):
        self.store.claim(state or self.state, REQUEST, worker_id='worker-1', caller_identity=CONTROLLER_IDENTITY, now=NOW)

    def test_enqueue_checks_full_persisted_state_atomically_with_unique_insert(self):
        self.enqueue()
        guard, _, _, put = self.client.calls[-1]['TransactItems']
        check = guard['ConditionCheck']
        self.assertEqual(check['ExpressionAttributeValues'][':payload'],
                         DynamoDBStateStore._serialize_state(self.state)['payload'])
        self.assertEqual(check['ExpressionAttributeValues'][':v'], {'N': '3'})
        self.assertEqual(check['ConditionExpression'], '#v = :v AND payload = :payload')
        self.assertEqual(put['Put']['ConditionExpression'], 'attribute_not_exists(PK) AND attribute_not_exists(SK)')
        self.assertNotIn('ttl', put['Put']['Item'])

    def test_changed_commit_or_input_cannot_create_another_job_for_same_lease(self):
        first = self.enqueue()
        original = self.client.calls[-1]['TransactItems'][-1]['Put']['Item']
        second = self.enqueue(request=replace(REQUEST, source_commit='d' * 40, input_digest='sha256:' + 'e' * 64))
        changed = self.client.calls[-1]['TransactItems'][-1]['Put']['Item']
        self.assertEqual(first, second)
        self.assertEqual(original['SK'], changed['SK'])
        self.assertNotEqual(original['binding'], changed['binding'])

    def test_claim_has_ready_only_condition_and_rechecks_authoritative_state(self):
        self.claim()
        guard, _, _, update = self.client.calls[-1]['TransactItems']
        self.assertEqual(guard['ConditionCheck']['Key']['SK'], {'S': 'STATE'})
        self.assertEqual(update['Update']['ConditionExpression'], '#s = :ready AND binding = :binding')
        self.assertEqual(update['Update']['ExpressionAttributeValues'][':ready'], {'S': 'READY'})
        self.assertEqual(update['Update']['ExpressionAttributeValues'][':started'], {'S': 'STARTED'})
        # No reusable transaction token: replay must fail the READY condition.
        self.assertNotIn('ClientRequestToken', self.client.calls[-1])

    def test_paused_expired_revoked_and_wrong_role_work_cannot_enqueue_or_claim(self):
        lease = self.state.leases[0]
        bad_states = [replace(self.state, state='PAUSED'),
                      replace(self.state, leases=(replace(lease, expires_at=NOW),)),
                      replace(self.state, leases=(replace(lease, revoked=True),)),
                      replace(self.state, state='QA')]
        for state in bad_states:
            for action in (self.enqueue, self.claim):
                with self.subTest(state=state), self.assertRaises((AuthorityError, LeaseError)):
                    action(state)
        self.assertEqual(self.client.calls, [])

    def test_no_agent_or_owner_string_can_impersonate_controller_adapter(self):
        for caller in ('engineering_agent_service', 'independent_inspector_service', 'tim_brydges'):
            with self.assertRaises(AuthorityError):
                self.store.enqueue(self.state, REQUEST, caller_identity=caller, now=NOW)
        self.assertEqual(self.client.calls, [])

    def test_production_dispatch_must_use_existing_release_authorization(self):
        lease = Lease('lease-1', 'release_automation', 'github_actions_production_environment', NOW + timedelta(minutes=5))
        with self.assertRaises(AuthorityError):
            self.enqueue(replace(self.state, state='RELEASE_READY', leases=(lease,)))
        self.assertEqual(self.client.calls, [])

    def test_restart_reads_started_record_without_mutation_or_reclaim(self):
        self.enqueue()
        item = self.client.calls[-1]['TransactItems'][-1]['Put']['Item']
        self.client.item = {**item, 'status': {'S': 'STARTED'}, 'worker_id': {'S': 'lost-worker'}}
        self.client.calls.clear()
        restarted = DynamoDBDispatchStore('state-table', self.client)
        self.assertEqual(restarted.read(self.state, REQUEST)['status'], {'S': 'STARTED'})
        self.assertEqual(len(self.client.calls), 1)
        self.assertTrue(self.client.calls[0]['ConsistentRead'])

    def test_read_conflicting_binding_fails_without_modifying_record(self):
        self.enqueue()
        self.client.item = self.client.calls[-1]['TransactItems'][-1]['Put']['Item']
        with self.assertRaises(StateError):
            self.store.read(self.state, replace(REQUEST, contract_digest='sha256:' + 'd' * 64))

    def test_receipt_is_worker_bound_idempotent_and_not_authoritative_evidence(self):
        paused = replace(self.state, state='PAUSED')
        self.store.record_receipt(paused, REQUEST, worker_id='worker-1', receipt_digest='sha256:' + 'f' * 64,
                                  caller_identity=CONTROLLER_IDENTITY)
        call = self.client.calls[-1]
        self.assertIn('worker_id = :worker', call['ConditionExpression'])
        self.assertIn('#s = :recorded AND receipt_digest = :receipt', call['ConditionExpression'])
        self.assertEqual(call['ExpressionAttributeValues'][':recorded'], {'S': 'RECEIPT_RECORDED'})
        self.assertEqual(call['Key']['SK'], {'S': 'DISPATCH#lease-1'})
        self.assertEqual(paused.state, 'PAUSED')

    def test_enqueue_and_claim_both_require_owner_objective_and_independent_scope(self):
        for action in (self.enqueue, self.claim):
            action()
            checks = self.client.calls[-1]['TransactItems']
            self.assertEqual(len(checks), 4)
            capability, review = [x['ConditionCheck'] for x in checks[1:3]]
            self.assertEqual(capability['Key']['PK'], {'S': 'FACTORY#factory#OBJECTIVE#factory-autonomy'})
            self.assertEqual(capability['Key']['SK'], {'S': 'CAPABILITY#durable-dispatch'})
            self.assertEqual(capability['ExpressionAttributeValues'][':open'], {'S': 'OPEN'})
            self.assertEqual(capability['ExpressionAttributeValues'][':owner'], {'S': 'tim_brydges'})
            self.assertIn('contract_digest = :contract', capability['ConditionExpression'])
            self.assertIn('reviewer_identity <> :executor', review['ConditionExpression'])
            self.assertEqual(review['ExpressionAttributeValues'][':executor'], {'S': 'engineering_agent_service'})
            self.assertIn('attribute_exists(review_evidence_digest)', review['ConditionExpression'])
            self.assertEqual(review['ExpressionAttributeValues'][':binding'],
                             {'S': self.store._binding(REQUEST)})

    def test_completed_or_missing_scope_cannot_fall_back_to_lease_only_dispatch(self):
        class RejectScope(RecordingClient):
            def transact_write_items(self, **kwargs):
                # Represents the database rejecting either scope condition.
                if len(kwargs['TransactItems']) != 4:
                    raise AssertionError('scope checks missing')
                raise StateError('TransactionCanceledException: scope condition failed')
        self.client = RejectScope()
        self.store = DynamoDBDispatchStore('state-table', self.client)
        for action in (self.enqueue, self.claim):
            with self.assertRaisesRegex(StateError, 'scope condition failed'):
                action()
        self.assertEqual(self.client.calls, [])

    def test_scope_binding_changes_require_new_review_but_never_reopen_same_lease(self):
        first = self.enqueue()
        binding = self.client.calls[-1]['TransactItems'][2]['ConditionCheck']['ExpressionAttributeValues'][':binding']
        changed = replace(REQUEST, capability_id='unrelated-product-polish')
        self.assertEqual(first, self.enqueue(request=changed))
        next_binding = self.client.calls[-1]['TransactItems'][2]['ConditionCheck']['ExpressionAttributeValues'][':binding']
        self.assertNotEqual(binding, next_binding)

    def test_scope_identifiers_are_required_and_cannot_be_blank(self):
        for key in ('objective_id', 'capability_id'):
            with self.assertRaises(StateError):
                replace(REQUEST, **{key: ''})

    def test_invalid_time_and_binding_rejected_before_io(self):
        for now in (NOW.replace(tzinfo=None), NOW - timedelta(seconds=1)):
            with self.assertRaises(StateError):
                self.store.enqueue(self.state, REQUEST, caller_identity=CONTROLLER_IDENTITY, now=now)
        with self.assertRaises(StateError):
            replace(REQUEST, source_commit='main')
        self.assertEqual(self.client.calls, [])


if __name__ == '__main__':
    unittest.main()
