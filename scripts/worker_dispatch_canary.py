"""Model-free worker integration proof; synthetic signers, no autonomous activation."""
import json
import re
import sys
import tempfile
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from scripts.scope_dispatch_canary import AwsCliDynamoDB, fixture_keys, sign
from factory_state.dispatch import DispatchRequest, DynamoDBDispatchStore
from factory_state.dynamodb import DynamoDBStateStore
from factory_state.model import CONTROLLER_IDENTITY, Lease, TaskState, StateError
from factory_state.scope import SignedScopeStore
from factory_runtime.worker import DispatchWorker, SignedResult, digest


def run(client, table, run_id, commit, *, now=None):
    if not re.fullmatch(r'[0-9]+-[0-9]+', run_id) or not re.fullmatch(r'[a-f0-9]{40}', commit):
        raise ValueError('exact run and source identities required')
    now = now or datetime.now(timezone.utc)
    task = 'scope-canary-' + run_id  # Reuse existing exact two-partition session policy.
    contract = b'Factory worker integration fixture; no models or release'
    input_bytes = task.encode()
    ledger = DynamoDBDispatchStore(table, client)
    states = DynamoDBStateStore(table, client)
    checks = []
    times = {'issued_at': int(now.timestamp()), 'expires_at': int(now.timestamp()) + 600}
    with tempfile.TemporaryDirectory(prefix='worker-fixture-') as directory:
        keys, private = fixture_keys(directory, ('tim_brydges', 'independent_inspector_service',
                                                'engineering_agent_service'))
        writer = SignedScopeStore(table, client, keys)
        state = TaskState('tims-software-factory', task, 'IMPLEMENTATION', 1, now, CONTROLLER_IDENTITY,
            (Lease('fixture-1', 'engineering_agent', 'engineering_agent_service', now + timedelta(minutes=10)),))
        request = DispatchRequest('fixture-1', task, 'worker-integration', commit, digest(contract), digest(input_bytes))
        item = states._serialize_state(state); item['SK'] = {'S': 'STATE'}
        client.put_item(TableName=table, Item=item, ConditionExpression='attribute_not_exists(PK) AND attribute_not_exists(SK)')
        cap = {'kind': 'capability', 'factory_id': state.factory_id, 'objective_id': task,
            'capability_id': request.capability_id, 'contract_digest': request.contract_digest,
            'owner_identity': 'tim_brydges', 'required_evidence': 'Worker restart and result binding checks',
            'stop_condition': 'Close and pause after bounded model-free checks', **times}
        writer.approve_capability(state, request, cap, sign(cap, private['tim_brydges'], directory), now=now)

        def enqueue(current, req):
            review = {'kind': 'scope_review', 'factory_id': current.factory_id, 'task_id': task,
                'binding': ledger._binding(req), 'verdict': 'ACCEPTED',
                'reviewer_identity': 'independent_inspector_service',
                'rationale': 'Synthetic verification only; not a real reviewer verdict', **times}
            writer.approve_task(current, req, review, sign(review, private['independent_inspector_service'], directory), now=now)
            ledger.enqueue(current, req, caller_identity=CONTROLLER_IDENTITY, now=now)

        class FixtureExecutor:
            identity = 'engineering_agent_service'
            calls = 0
            reservations = 0
            mode = 'success'

            def check_activation(self, *args, **kwargs):
                if self.mode == 'disabled':
                    raise StateError('fixture activation denied')

            def reserve(self, *args, **kwargs):
                self.reservations += 1
                if self.mode == 'pause':
                    paused = replace(state, state='PAUSED', version=state.version + 1,
                                     leases=tuple(replace(x, revoked=True) for x in state.leases))
                    row = states._serialize_state(paused); row['SK'] = {'S': 'STATE'}
                    client.put_item(TableName=table, Item=row)

            def execute(self, current, req, *, dispatch_id, input_bytes):
                self.calls += 1
                if self.mode == 'crash':
                    raise RuntimeError('simulated lost external response')
                output = b'bounded deterministic fixture result'
                payload = {'kind': 'role_result', 'factory_id': current.factory_id, 'task_id': task,
                    'binding': ledger._binding(req), 'dispatch_id': dispatch_id,
                    'producer_identity': self.identity, 'output_digest': digest(output), **times}
                signer = 'independent_inspector_service' if self.mode == 'wrong-signer' else self.identity
                return SignedResult(payload, sign(payload, private[signer], directory), output)

        executor = FixtureExecutor()
        def worker(worker_id='fixture-worker'):
            return DispatchWorker(states, ledger, deployed_commit=commit, worker_id=worker_id,
                key_loader=lambda at: keys, executors={'engineering_agent': executor}, clock=lambda: now)
        def invoke(worker_id='fixture-worker', **overrides):
            return worker(worker_id).run(state.factory_id, task, request,
                input_bytes=overrides.get('input_bytes', input_bytes), contract_bytes=contract)
        def blocked(action, expected=StateError):
            try:
                action()
            except expected:
                return
            raise AssertionError('unsafe worker execution accepted')

        enqueue(state, request)
        blocked(lambda: invoke(input_bytes=b'changed'))
        executor.mode = 'disabled'; blocked(invoke)
        assert executor.calls == executor.reservations == 0
        checks.append('input_and_activation_rejected_before_claim')
        executor.mode = 'success'
        receipt = invoke()
        assert receipt['status'] == 'RECEIPT_RECORDED'
        assert invoke('restarted-worker') == receipt and executor.calls == executor.reservations == 1
        row = ledger.read(state, request)
        assert all(key in row for key in ('result_payload', 'result_signature', 'result_output'))
        checks += ['signed_role_result_persisted', 'restart_does_not_repeat_completed_call']

        for index, mode in enumerate(('crash', 'wrong-signer', 'revoked-reviewer', 'pause'), 2):
            # New synthetic lease/state version for each separately bound scenario.
            state = replace(state, version=index,
                leases=(replace(state.leases[0], lease_id=f'fixture-{index}'),))
            request = replace(request, lease_id=f'fixture-{index}')
            row = states._serialize_state(state); row['SK'] = {'S': 'STATE'}
            client.put_item(TableName=table, Item=row)
            enqueue(state, request)
            executor.mode = mode
            before_calls = executor.calls
            if mode == 'revoked-reviewer':
                removed = keys.pop('independent_inspector_service')
                blocked(invoke)
                keys['independent_inspector_service'] = removed
                assert ledger.read(state, request)['status'] == {'S': 'READY'}
                checks.append('revoked_reviewer_blocks_ready_work')
                continue
            if mode == 'pause':
                # Require an actual transaction cancellation; unexpected AWS errors fail.
                try:
                    invoke()
                except Exception as error:
                    from scripts.scope_dispatch_canary import DynamoFailure
                    if not (isinstance(error, DynamoFailure) or
                        getattr(error, 'response', {}).get('Error', {}).get('Code') == 'TransactionCanceledException'):
                        raise
                else:
                    raise AssertionError('pause failed to block execution')
                assert executor.calls == before_calls
                checks.append('pause_after_reservation_blocks_external_call')
            else:
                blocked(invoke, RuntimeError if mode == 'crash' else StateError)
                assert executor.calls == before_calls + 1
                checks.append('lost_response_not_retried' if mode == 'crash' else 'wrong_result_signer_rejected')
            assert invoke('replacement-worker')['status'] == 'NEEDS_RECONCILIATION'
            assert executor.calls == before_calls + (0 if mode == 'pause' else 1)

        capkey = {'PK': {'S': f'FACTORY#{state.factory_id}#TASK#SCOPE#OBJECTIVE#{task}'},
                  'SK': {'S': 'CAPABILITY#worker-integration'}}
        client.update_item(TableName=table, Key=capkey, UpdateExpression='SET #s=:s',
            ExpressionAttributeNames={'#s': 'status'}, ExpressionAttributeValues={':s': {'S': 'COMPLETE'}})
        assert states.load_state(state.factory_id, task).state == 'PAUSED'
        checks.append('fixture_closed_and_paused')
    return {'schema_version': '1.0', 'conclusion': 'success', 'source_commit': commit,
        'run_id': run_id, 'task_id': task, 'checks': checks, 'model_calls': 0,
        'production_deployments': 0, 'synthetic_signers': True,
        'independent_review_proven': False, 'continuous_worker_activated': False}


if __name__ == '__main__':
    print(json.dumps(run(AwsCliDynamoDB(), 'tims-software-factory-state', sys.argv[1], sys.argv[2]), indent=2))
