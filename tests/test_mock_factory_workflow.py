"""Real intake, signatures, worker and progression; mock providers/persistence.

This checks orchestration, not DynamoDB concurrency or real provider quality.
No credentials, network clients, live signers or deployment flags are used.
"""
import base64
import json
import tempfile
import unittest
from datetime import datetime, timezone

from factory_runtime.autonomy import AutonomousCycle
from factory_runtime.intake import AuthenticatedIntakeService, STATE_ROLES
from factory_runtime.progression import SignedResultProgressor
from factory_runtime.receipt_transport import ReceiptVersions, SignedReceiptBundle, receipt_plan_digest
from factory_runtime.worker import DispatchWorker, SignedResult, digest
from factory_state.model import CONTROLLER_IDENTITY, ROLE_IDENTITIES, StateError, TaskState
from factory_state.scope import canonical
from scripts.scope_dispatch_canary import fixture_keys, sign
from test_authenticated_intake import MemoryClient, MemoryLedger
from test_inspection_completion import CheckedStates

NOW = datetime(2026, 10, 2, 20, tzinfo=timezone.utc)


class Ledger(MemoryLedger):
    def claim(self, state, request, *, worker_id, now, **kwargs):
        self._state_guard(state, request, now)
        row = self.rows[request.lease_id]
        if row['status'] != {'S': 'READY'}: raise StateError('duplicate claim')
        row.update(status={'S': 'STARTED'}, worker_id={'S': worker_id})

    def assert_started(self, state, request, *, worker_id, now):
        self._state_guard(state, request, now)
        row = self.rows[request.lease_id]
        if row['status'] != {'S': 'STARTED'} or row['worker_id'] != {'S': worker_id}:
            raise StateError('wrong claim')

    def record_signed_result(self, state, request, *, worker_id, payload, signature, output):
        row = self.rows[request.lease_id]
        if row['status'] != {'S': 'STARTED'} or row['worker_id'] != {'S': worker_id}:
            raise StateError('wrong result claim')
        receipt = digest(canonical(payload))
        row.update(status={'S': 'RECEIPT_RECORDED'}, receipt_digest={'S': receipt},
            result_payload={'S': json.dumps(payload)},
            result_signature={'S': base64.b64encode(signature).decode()},
            result_output={'S': base64.b64encode(output).decode()})
        return receipt


class MockWorkflowTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.keys, self.private = fixture_keys(self.directory.name,
            ('tim_brydges', *[ROLE_IDENTITIES[role] for role in STATE_ROLES.values()]))
        self.states = CheckedStates(TaskState('mock-factory', 'mock-task',
            'SPECIFICATION', 0, NOW, CONTROLLER_IDENTITY))
        self.ledger = Ledger(MemoryClient())
        self.intake = AuthenticatedIntakeService(self.states, self.ledger,
            key_loader=lambda now: self.keys, clock=lambda: NOW)
        self.progressor = SignedResultProgressor(self.states, self.ledger,
            key_loader=lambda now: self.keys, clock=lambda: NOW)
        self.calls = []

    def step(self, *, failure=None):
        state = self.states.state
        role = STATE_ROLES[state.state]
        reviewer = ('product_spec_reviewer_service' if role == 'independent_inspector'
                    else 'independent_inspector_service')
        plan = self.intake.prepare(state.factory_id, state.task_id, role_id=role,
            source_commit='a'*40, objective_id='mock-only', capability_id='mock-'+state.state,
            contract_bytes=b'mock contract', input_bytes=b'mock input', reviewer_identity=reviewer,
            required_evidence='signed mock output', stop_condition='stop at RELEASE_READY',
            rationale='synthetic fixture, not production approval')
        fixture = self
        class Receipts:
            def load(self, supplied, versions):
                return SignedReceiptBundle(receipt_plan_digest(supplied),
                    sign(supplied.capability_payload, fixture.private['tim_brydges'], fixture.directory.name),
                    sign(supplied.review_payload, fixture.private[reviewer], fixture.directory.name))
        class Executor:
            identity = ROLE_IDENTITIES[role]
            def check_activation(self, *args, **kwargs): pass
            def reserve(self, *args, **kwargs): pass
            def execute(self, current, request, *, dispatch_id, input_bytes):
                fixture.calls.append(role)
                if failure == 'timeout': raise TimeoutError('unknown mock provider outcome')
                output = b'deterministic mock role output'
                payload = {'kind': 'role_result', 'factory_id': current.factory_id,
                    'task_id': current.task_id, 'binding': fixture.ledger._binding(request),
                    'dispatch_id': dispatch_id, 'producer_identity': self.identity,
                    'output_digest': digest(output), 'issued_at': int(NOW.timestamp()),
                    'expires_at': int(NOW.timestamp())+600}
                signature = sign(payload, fixture.private[self.identity], fixture.directory.name)
                if failure == 'signature': signature = bytes(64)
                return SignedResult(payload, signature, output)
        worker = DispatchWorker(self.states, self.ledger, deployed_commit='a'*40,
            worker_id='mock-worker', key_loader=lambda now: self.keys,
            executors={role: Executor()}, clock=lambda: NOW)
        cycle = AutonomousCycle(self.intake, worker, self.progressor, Receipts(), enabled=True)
        run = lambda: cycle.step(plan, ReceiptVersions('mock-owner', 'mock-review'),
                                input_bytes=b'mock input', contract_bytes=b'mock contract')
        return run

    def test_all_seven_gates_stop_before_release_and_duplicates_do_not_call_provider(self):
        stages = []
        while self.states.state.state != 'RELEASE_READY':
            stages.append(self.states.state.state)
            run = self.step()
            self.assertEqual(run()['status'], 'ADVANCED')
            count = len(self.calls)
            replay = run()
            self.assertEqual(replay['status'], 'ALREADY_ADVANCED')
            self.assertFalse(replay['release_dispatched'])
            self.assertEqual(len(self.calls), count)
        self.assertEqual(stages, list(STATE_ROLES))
        self.assertEqual(len(self.calls), 7)
        self.assertEqual(len(self.states.state.leases), 7)
        self.assertEqual(len(self.states.state.consumed_evidence_ids), 7)
        self.assertTrue(all(x.revoked for x in self.states.state.leases))

    def test_timeout_and_invalid_signature_stop_without_retry_or_progression(self):
        for failure, error in [('timeout', TimeoutError), ('signature', StateError)]:
            with self.subTest(failure=failure):
                # Each failure has its own isolated task/ledger and allowance.
                self.states.state = TaskState('mock-factory', 'mock-'+failure,
                    'IMPLEMENTATION', 0, NOW, CONTROLLER_IDENTITY)
                self.ledger.rows.clear()
                self.ledger.client.items.clear()
                run = self.step(failure=failure)
                before = len(self.calls)
                with self.assertRaises(error): run()
                self.assertEqual(run()['status'], 'NEEDS_RECONCILIATION')
                self.assertEqual(len(self.calls), before + 1)
                self.assertEqual(self.states.state.state, 'IMPLEMENTATION')


if __name__ == '__main__': unittest.main()
