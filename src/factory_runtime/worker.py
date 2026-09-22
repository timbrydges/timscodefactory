"""One bounded controller-owned dispatch; no implicit retries, release or activation.

The deployment supplies authenticated role adapters, activation/budget checks,
and a fresh trusted-key loader. These are privileged dependencies, not job data.
An executor must enforce its own pause/credential/budget controls at each external
effect; the controller's last check cannot make a remote side effect atomic.
"""
from dataclasses import dataclass
from typing import Protocol
import hashlib

from factory_state.dispatch import DispatchRequest
from factory_state.model import CONTROLLER_IDENTITY, COMMIT_SHA, SAFE_IDENTIFIER, StateError
from factory_state.scope import SignedScopeStore


def digest(raw: bytes) -> str:
    return 'sha256:' + hashlib.sha256(raw).hexdigest()


@dataclass(frozen=True)
class SignedResult:
    payload: dict
    signature: bytes
    output: bytes


class RoleExecutor(Protocol):
    # The transport must authenticate this identity; a role label is insufficient.
    identity: str

    def check_activation(self, state, request, *, now): ...
    def reserve(self, state, request, *, dispatch_id, now): ...
    def execute(self, state, request, *, dispatch_id, input_bytes) -> SignedResult: ...


class DispatchWorker:
    def __init__(self, state_store, ledger, *, deployed_commit, worker_id,
                 key_loader, executors: dict[str, RoleExecutor], clock):
        if not COMMIT_SHA.fullmatch(deployed_commit) or not SAFE_IDENTIFIER.fullmatch(worker_id):
            raise StateError('worker needs exact source and execution identities')
        self.states, self.ledger = state_store, ledger
        self.commit, self.worker_id = deployed_commit, worker_id
        self.key_loader, self.executors, self.clock = key_loader, dict(executors), clock

    def _scope(self, now):
        return SignedScopeStore(self.ledger.table_name, self.ledger.client, self.key_loader(now))

    def run(self, factory_id, task_id, request: DispatchRequest, *, input_bytes, contract_bytes):
        if (request.source_commit != self.commit or digest(input_bytes) != request.input_digest or
                digest(contract_bytes) != request.contract_digest):
            raise StateError('worker source, input or contract differs from approved binding')
        state = self.states.load_state(factory_id, task_id)
        if state is None:
            raise StateError('authoritative task state missing')
        record = self.ledger.read(state, request)
        if record is None:
            return {'status': 'NOT_QUEUED'}
        status = record['status']['S']
        if status == 'STARTED':
            return {'status': 'NEEDS_RECONCILIATION', 'dispatch_id': record['dispatch_id']['S']}
        if status == 'RECEIPT_RECORDED':
            return {'status': 'RECEIPT_RECORDED', 'receipt_digest': record['receipt_digest']['S']}
        if status != 'READY':
            raise StateError('unknown dispatch status')
        lease = next((x for x in state.leases if x.lease_id == request.lease_id), None)
        executor = self.executors.get(lease.role_id) if lease else None
        if executor is None or executor.identity != lease.authoritative_identity:
            raise StateError('authenticated role executor is not configured')
        now = self.clock()
        self._scope(now).verify_persisted(state, request, now=now)
        executor.check_activation(state, request, now=now)
        self.ledger.claim(state, request, worker_id=self.worker_id,
                          caller_identity=CONTROLLER_IDENTITY, now=self.clock())
        # From here, all failures leave STARTED: never reclaim or repeat a call.
        dispatch_id = record['dispatch_id']['S']
        executor.reserve(state, request, dispatch_id=dispatch_id, now=self.clock())
        now = self.clock()
        scope = self._scope(now)
        scope.verify_persisted(state, request, now=now)
        executor.check_activation(state, request, now=now)
        self.ledger.assert_started(state, request, worker_id=self.worker_id, now=self.clock())
        result = executor.execute(state, request, dispatch_id=dispatch_id, input_bytes=input_bytes)
        now = self.clock()
        expected = {'kind': 'role_result', 'factory_id': factory_id, 'task_id': task_id,
                    'binding': self.ledger._binding(request), 'dispatch_id': dispatch_id,
                    'producer_identity': lease.authoritative_identity,
                    'output_digest': digest(result.output)}
        if (set(result.payload) != set(expected) | {'issued_at', 'expires_at'} or
                any(result.payload.get(k) != v for k, v in expected.items())):
            raise StateError('signed role result does not match dispatch')
        # Fresh keys again: a key revoked during execution cannot approve a result.
        self._scope(now)._verify(result.payload, result.signature, lease.authoritative_identity, now)
        receipt = self.ledger.record_signed_result(state, request, worker_id=self.worker_id,
            payload=result.payload, signature=result.signature, output=result.output)
        return {'status': 'RECEIPT_RECORDED', 'receipt_digest': receipt}
