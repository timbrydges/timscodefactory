"""Isolated service/transport integration with simulated AWS and real signatures."""
import base64
import io
import json
import sys
import tempfile
import unittest
from dataclasses import asdict, replace
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT)); sys.path.insert(0, str(ROOT/'src'))
from scripts.scope_dispatch_canary import fixture_keys, sign
from factory_runtime.cloud_roles import LambdaRoleExecutor, RoleExecutionService, ROLE_IDENTITIES
from factory_runtime.worker import DispatchWorker, digest
from factory_state.dispatch import DispatchRequest, DynamoDBDispatchStore
from factory_state.dynamodb import DynamoDBStateStore
from factory_state.model import CONTROLLER_IDENTITY, StateError
from factory_state.scope import SignedScopeStore
from test_dispatch_ledger import NOW, snapshot
try:
    import boto3
    from moto import mock_aws
except ImportError:
    mock_aws = None


@unittest.skipIf(mock_aws is None, 'Requires moto[dynamodb]')
class CloudRoleTests(unittest.TestCase):
    def setUp(self):
        self.aws = mock_aws(); self.aws.start(); self.addCleanup(self.aws.stop)
        self.directory = tempfile.TemporaryDirectory(); self.addCleanup(self.directory.cleanup)
        identities = ('tim_brydges', 'product_spec_reviewer_service', *ROLE_IDENTITIES.values())
        self.keys, self.private = fixture_keys(self.directory.name, identities)
        self.db = boto3.client('dynamodb', region_name='ca-central-1')
        self.db.create_table(TableName='role-state',
            KeySchema=[{'AttributeName': 'PK', 'KeyType': 'HASH'}, {'AttributeName': 'SK', 'KeyType': 'RANGE'}],
            AttributeDefinitions=[{'AttributeName': x, 'AttributeType': 'S'} for x in ('PK', 'SK')],
            BillingMode='PAY_PER_REQUEST')
        self.states = DynamoDBStateStore('role-state', self.db)
        self.ledger = DynamoDBDispatchStore('role-state', self.db)
        self.calls = self.invocations = 0
        self.mode = 'success'
        self.setup_role('builder')

    def setup_role(self, role):
        self.role = role; identity = ROLE_IDENTITIES[role]
        role_id, state_name = {'builder': ('engineering_agent', 'IMPLEMENTATION'),
            'planner': ('software_architect', 'ARCHITECTURE'),
            'inspector': ('independent_inspector', 'INSPECTION')}[role]
        base = snapshot()
        self.state = replace(base, task_id='task-' + role, state=state_name,
            leases=(replace(base.leases[0], authoritative_identity=identity, role_id=role_id),))
        self.input = b'bounded input'; self.contract = b'test-only no provider budget'
        self.request = DispatchRequest('lease-1', 'factory-objective', 'remote-role', 'a'*40,
            digest(self.contract), digest(self.input))
        row = self.states._serialize_state(self.state); row['SK'] = {'S': 'STATE'}
        self.db.put_item(TableName='role-state', Item=row)
        scope = SignedScopeStore('role-state', self.db, self.keys)
        times = {'issued_at': int(NOW.timestamp()), 'expires_at': int(NOW.timestamp()) + 300}
        cap = {'kind': 'capability', 'factory_id': self.state.factory_id,
            'objective_id': self.request.objective_id, 'capability_id': self.request.capability_id,
            'contract_digest': self.request.contract_digest, 'owner_identity': 'tim_brydges',
            'required_evidence': 'Test fixture', 'stop_condition': 'End fixture', **times}
        # The same owner capability is shared by these independent task fixtures.
        if role == 'builder':
            scope.approve_capability(self.state, self.request, cap,
                sign(cap, self.private['tim_brydges'], self.directory.name), now=NOW)
        review = {'kind': 'scope_review', 'factory_id': self.state.factory_id,
            'task_id': self.state.task_id, 'binding': self.ledger._binding(self.request),
            'reviewer_identity': 'product_spec_reviewer_service', 'verdict': 'ACCEPTED',
            'rationale': 'Independent synthetic fixture', **times}
        scope.approve_task(self.state, self.request, review,
            sign(review, self.private['product_spec_reviewer_service'], self.directory.name), now=NOW)
        self.dispatch = self.ledger.enqueue(self.state, self.request, caller_identity=CONTROLLER_IDENTITY, now=NOW)
        test = self
        class Signer:
            def sign(self, payload, *, now):
                chosen = 'tim_brydges' if test.mode == 'wrong-signer' else identity
                return sign(payload, test.private[chosen], test.directory.name)
        signer = Signer(); signer.identity = identity
        class Backend:
            def check_activation(self, *args, **kwargs):
                if test.mode == 'disabled': raise StateError('disabled')
            def reserve(self, *args, **kwargs):
                if test.mode == 'pause':
                    paused = replace(test.state, state='PAUSED', version=4)
                    row = test.states._serialize_state(paused); row['SK'] = {'S': 'STATE'}
                    test.db.put_item(TableName='role-state', Item=row)
            def execute(self, *args, **kwargs):
                test.calls += 1
                if test.mode == 'crash': raise TimeoutError('uncertain provider outcome')
                return b'role result'
        self.service = RoleExecutionService(self.states, self.ledger, deployed_commit='a'*40,
            identity=identity, key_loader=lambda now: self.keys, signer=signer,
            backend=Backend(), clock=lambda: NOW)
        class Client:
            meta = SimpleNamespace(config=SimpleNamespace(retries={'total_max_attempts': 1}),
                endpoint_url='https://lambda.ca-central-1.amazonaws.com')
            def invoke(self, **kwargs):
                test.invocations += 1; test.last_invocation = kwargs
                test.last_event = json.loads(kwargs['Payload'])
                result = test.service.handle(test.last_event)
                if test.mode == 'lost-response': raise TimeoutError('response lost')
                return {'StatusCode': 200, 'ExecutedVersion': '1', 'Payload': io.BytesIO(json.dumps(result).encode())}
        self.client = Client()
        self.executor = LambdaRoleExecutor(self.client,
            function_arn=f'arn:aws:lambda:ca-central-1:666730517561:function:tims-factory-{role}:1',
            worker_id='worker-1', guard=Backend())
        self.worker = DispatchWorker(self.states, self.ledger, deployed_commit='a'*40, worker_id='worker-1',
            key_loader=lambda now: self.keys, executors={role_id: self.executor}, clock=lambda: NOW)

    def run_worker(self):
        return self.worker.run(self.state.factory_id, self.state.task_id, self.request,
            input_bytes=self.input, contract_bytes=self.contract)

    def test_all_three_roles_return_signed_results_and_replay_without_work(self):
        for role in ('builder', 'planner', 'inspector'):
            if role != 'builder': self.setup_role(role)
            with self.subTest(role=role):
                before = self.calls
                result = self.run_worker()
                self.assertEqual(result['status'], 'RECEIPT_RECORDED')
                self.assertEqual(self.run_worker(), result)
                self.service.handle(self.last_event)
                self.assertEqual(self.calls, before + 1)
                self.assertEqual(self.last_invocation['InvocationType'], 'RequestResponse')
                self.assertNotIn('credentials', self.last_event)

    def test_lost_response_leaves_started_and_recovers_evidence_without_execution(self):
        self.mode = 'lost-response'
        with self.assertRaises(TimeoutError): self.run_worker()
        self.assertEqual(self.run_worker()['status'], 'NEEDS_RECONCILIATION')
        recovered = self.service.handle(self.last_event)
        self.assertEqual(base64.b64decode(recovered['output_base64']), b'role result')
        self.assertEqual(self.calls, 1); self.assertEqual(self.invocations, 1)

    def test_crash_and_redelivery_cannot_repeat_provider_call(self):
        self.mode = 'crash'
        with self.assertRaises(TimeoutError): self.run_worker()
        with self.assertRaises(StateError): self.service.handle(self.last_event)
        self.assertEqual(self.calls, 1)
        self.assertEqual(self.run_worker()['status'], 'NEEDS_RECONCILIATION')

    def test_reviewer_revocation_rejects_before_role_work(self):
        del self.keys['product_spec_reviewer_service']
        with self.assertRaises(StateError): self.run_worker()
        self.assertEqual(self.calls, 0); self.assertEqual(self.invocations, 0)

    def test_wrong_signature_cannot_be_persisted_as_complete(self):
        self.mode = 'wrong-signer'
        with self.assertRaises(StateError): self.run_worker()
        with self.assertRaises(StateError): self.service.handle(self.last_event)
        self.assertEqual(self.calls, 1)

    def test_remote_pause_after_reservation_blocks_execution(self):
        # Invoke the role directly after a valid controller claim so the pause is remote.
        self.ledger.claim(self.state, self.request, worker_id='worker-1', caller_identity=CONTROLLER_IDENTITY, now=NOW)
        self.mode = 'pause'
        with self.assertRaises(self.db.exceptions.TransactionCanceledException):
            self.executor.execute(self.state, self.request, dispatch_id=self.dispatch, input_bytes=self.input)
        self.assertEqual(self.calls, 0)

    def test_unclaimed_forged_worker_and_changed_input_rejected(self):
        event = {'schema_version': '1.0', 'factory_id': self.state.factory_id, 'task_id': self.state.task_id,
            'dispatch_id': self.dispatch, 'worker_id': 'worker-1', 'request': asdict(self.request),
            'input_base64': base64.b64encode(self.input).decode()}
        with self.assertRaises(StateError): self.service.handle(event)
        self.ledger.claim(self.state, self.request, worker_id='worker-1', caller_identity=CONTROLLER_IDENTITY, now=NOW)
        for patch in ({'worker_id': 'imposter'}, {'dispatch_id': 'wrong'}, {'input_base64': 'eA=='},
                      {'request': {**asdict(self.request), 'source_commit': 'b'*40}}):
            with self.assertRaises(StateError): self.service.handle({**event, **patch})
        self.assertEqual(self.calls, 0)

    def test_unversioned_alias_wrong_account_and_retrying_client_rejected(self):
        for arn in ('arn:aws:lambda:ca-central-1:666730517561:function:tims-factory-builder:latest',
                    'arn:aws:lambda:ca-central-1:000000000000:function:tims-factory-builder:1'):
            with self.assertRaises(StateError): LambdaRoleExecutor(self.client, function_arn=arn, worker_id='worker-1', guard=None)
        self.client.meta = SimpleNamespace(config=SimpleNamespace(retries={'total_max_attempts': 2}),
            endpoint_url='https://lambda.ca-central-1.amazonaws.com')
        with self.assertRaises(StateError): LambdaRoleExecutor(self.client,
            function_arn=self.executor.function_arn, worker_id='worker-1', guard=None)

    def test_remote_version_error_oversize_and_duplicate_fields_are_rejected(self):
        for response in (
            {'StatusCode': 200, 'ExecutedVersion': '2', 'Payload': io.BytesIO(b'{}')},
            {'StatusCode': 200, 'ExecutedVersion': '1', 'FunctionError': 'Unhandled', 'Payload': io.BytesIO(b'{}')},
            {'StatusCode': 200, 'ExecutedVersion': '1', 'Payload': io.BytesIO(b'x' * 131073)},
            {'StatusCode': 200, 'ExecutedVersion': '1', 'Payload': io.BytesIO(b'{"payload":{},"payload":{}}')},
        ):
            self.client.invoke = lambda **kwargs: response
            with self.assertRaises(StateError): self.executor.execute(self.state, self.request,
                dispatch_id=self.dispatch, input_bytes=self.input)
            self.assertTrue(response['Payload'].closed)

    def test_duplicate_delivery_race_has_one_role_side_claim(self):
        from concurrent.futures import ThreadPoolExecutor
        from threading import Barrier
        self.ledger.claim(self.state, self.request, worker_id='worker-1', caller_identity=CONTROLLER_IDENTITY, now=NOW)
        event = {'schema_version': '1.0', 'factory_id': self.state.factory_id, 'task_id': self.state.task_id,
            'dispatch_id': self.dispatch, 'worker_id': 'worker-1', 'request': asdict(self.request),
            'input_base64': base64.b64encode(self.input).decode()}
        barrier = Barrier(2)
        original = self.db.get_item
        def simultaneous_read(**kwargs):
            result = original(**kwargs)
            if kwargs['Key']['SK']['S'].startswith('EXECUTION#'):
                barrier.wait(timeout=5)
            return result
        self.db.get_item = simultaneous_read
        def attempt():
            try:
                self.service.handle(event)
                return 'complete'
            except self.db.exceptions.TransactionCanceledException:
                return 'claim-rejected'
        with ThreadPoolExecutor(max_workers=2) as pool:
            outcomes = list(pool.map(lambda _: attempt(), range(2)))
        self.assertEqual(sorted(outcomes), ['claim-rejected', 'complete'])
        self.assertEqual(self.calls, 1)
