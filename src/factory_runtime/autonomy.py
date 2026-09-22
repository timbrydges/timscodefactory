"""Restart-safe autonomous Factory execution; disabled unless explicitly enabled."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Protocol

from factory_state.model import COMMIT_SHA, SAFE_IDENTIFIER, SHA256_DIGEST, StateError
from .intake import STATE_ROLES, IntakePlan
from .receipt_transport import ReceiptVersions
from .worker import digest


@dataclass(frozen=True)
class ScheduledAutonomyJob:
    """Exact pre-reviewed material for one scheduler tick."""

    plan: IntakePlan
    receipt_versions: ReceiptVersions
    input_bytes: bytes
    contract_bytes: bytes


class ScheduledJobSource(Protocol):
    def load(self, factory_id: str, task_id: str, state) -> ScheduledAutonomyJob: ...


@dataclass(frozen=True)
class AutonomyActivation:
    """Deployment-owned bounds for one unattended task activation."""

    activation_id: str
    factory_id: str
    task_id: str
    source_commit: str
    contract_digest: str
    starts_at: datetime
    expires_at: datetime

    def validate(self, now: datetime) -> None:
        if (not isinstance(self.activation_id, str) or
                not SAFE_IDENTIFIER.fullmatch(self.activation_id) or
                not isinstance(self.factory_id, str) or
                not SAFE_IDENTIFIER.fullmatch(self.factory_id) or
                not isinstance(self.task_id, str) or not SAFE_IDENTIFIER.fullmatch(self.task_id) or
                not isinstance(self.source_commit, str) or
                not COMMIT_SHA.fullmatch(self.source_commit) or
                not isinstance(self.contract_digest, str) or
                not SHA256_DIGEST.fullmatch(self.contract_digest)):
            raise StateError('autonomy activation binding is incomplete')
        if (not isinstance(now, datetime) or now.tzinfo is None or now.utcoffset() is None or
                not isinstance(self.starts_at, datetime) or self.starts_at.tzinfo is None or
                self.starts_at.utcoffset() is None or not isinstance(self.expires_at, datetime) or
                self.expires_at.tzinfo is None or self.expires_at.utcoffset() is None or
                self.starts_at >= self.expires_at):
            raise StateError('autonomy activation window is invalid')
        if not self.starts_at <= now < self.expires_at:
            raise StateError('autonomy activation is outside its approved window')


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


class AutonomousScheduler:
    """Run at most one bounded, non-release Factory cycle per external tick."""

    def __init__(self, cycle, state_store, job_source: ScheduledJobSource, activation,
                 *, clock, enabled=False):
        if type(enabled) is not bool:
            raise StateError('autonomous scheduler activation must be explicit')
        self.cycle, self.states, self.jobs = cycle, state_store, job_source
        self.activation, self.clock, self.enabled = activation, clock, enabled

    def tick(self, factory_id: str, task_id: str):
        if not self.enabled:
            raise StateError('autonomous scheduler is disabled')
        now = self.clock()
        if not isinstance(self.activation, AutonomyActivation):
            raise StateError('autonomous scheduler lacks an exact activation')
        self.activation.validate(now)
        if (factory_id, task_id) != (self.activation.factory_id, self.activation.task_id):
            raise StateError('scheduler target differs from approved activation')
        state = self.states.load_state(factory_id, task_id)
        if state is None:
            raise StateError('autonomous scheduler task state missing')
        if state.state == 'RELEASE_READY':
            return {'status': 'RELEASE_READY', 'worker_invocations': 0,
                    'release_dispatched': False, 'activation_id': self.activation.activation_id}
        if state.state not in STATE_ROLES:
            return {'status': 'STOPPED', 'state': state.state, 'worker_invocations': 0,
                    'release_dispatched': False, 'activation_id': self.activation.activation_id}

        job = self.jobs.load(factory_id, task_id, state)
        if not isinstance(job, ScheduledAutonomyJob) or not isinstance(job.plan, IntakePlan):
            raise StateError('scheduler job source returned invalid material')
        plan = job.plan
        if ((plan.factory_id, plan.task_id, plan.state, plan.state_version) !=
                (factory_id, task_id, state.state, state.version) or
                plan.request.source_commit != self.activation.source_commit or
                plan.request.contract_digest != self.activation.contract_digest or
                digest(job.contract_bytes) != self.activation.contract_digest):
            raise StateError('scheduled job differs from approved activation or current state')
        result = self.cycle.step(plan, job.receipt_versions, input_bytes=job.input_bytes,
                                 contract_bytes=job.contract_bytes)
        invocations = result.get('worker_invocations')
        if (type(invocations) is not int or not 0 <= invocations <= 1 or
                result.get('release_dispatched') is not False):
            raise StateError('autonomous cycle exceeded scheduler authority')
        return {**result, 'activation_id': self.activation.activation_id}
