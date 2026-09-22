"""One restart-safe autonomous Factory cycle; disabled unless explicitly enabled."""
from __future__ import annotations

from factory_state.model import StateError
from .intake import IntakePlan
from .worker import digest


class AutonomousCycle:
    """Compose receipt transport, intake, one worker run and one gate advance."""
    def __init__(self, intake, worker, progressor, receipt_transport, *, enabled=False):
        if type(enabled) is not bool:
            raise StateError('autonomous cycle activation must be explicit')
        self.intake, self.worker, self.progressor = intake, worker, progressor
        self.receipts, self.enabled = receipt_transport, enabled

    def step(self, plan, versions, *, input_bytes, contract_bytes):
        if not self.enabled:
            raise StateError('autonomous cycle is disabled')
        if (not isinstance(plan, IntakePlan) or not isinstance(input_bytes, bytes) or
                not isinstance(contract_bytes, bytes) or digest(input_bytes) != plan.request.input_digest or
                digest(contract_bytes) != plan.request.contract_digest):
            raise StateError('autonomous cycle bytes differ from reviewed intake')
        state = self.intake.states.load_state(plan.factory_id, plan.task_id)
        if state is None: raise StateError('autonomous task state missing')
        row = self.intake.ledger.read(state, plan.request)
        if row is None:
            bundle = self.receipts.load(plan, versions)
            intake = self.intake.activate(plan, owner_signature=bundle.owner_signature,
                                          reviewer_signature=bundle.reviewer_signature)
            state = self.intake.states.load_state(plan.factory_id, plan.task_id)
            row = self.intake.ledger.read(state, plan.request)
        else:
            intake = {'status': 'ALREADY_QUEUED', 'dispatch_id': row['dispatch_id']['S']}
        status = row.get('status', {}).get('S') if row else None
        if status == 'RECEIPT_RECORDED':
            advanced = self.progressor.advance(plan.factory_id, plan.task_id, plan.request)
            return {'status': advanced['status'], 'intake': intake, 'worker_invocations': 0,
                    'progression': advanced, 'release_dispatched': False}
        worker = self.worker.run(plan.factory_id, plan.task_id, plan.request,
            input_bytes=input_bytes, contract_bytes=contract_bytes)
        if worker.get('status') != 'RECEIPT_RECORDED':
            return {'status': worker.get('status'), 'intake': intake, 'worker_invocations': 0,
                    'worker': worker, 'release_dispatched': False}
        advanced = self.progressor.advance(plan.factory_id, plan.task_id, plan.request)
        return {'status': advanced['status'], 'intake': intake, 'worker_invocations': 1,
                'worker': worker, 'progression': advanced, 'release_dispatched': False}
