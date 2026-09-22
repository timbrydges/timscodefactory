"""Restart-safe activation of one pre-reviewed Factory role dispatch.

Planning is non-mutating and produces exact payloads for the isolated owner and
reviewer signers. Activation verifies both signatures before issuing a lease,
then persists scope and queues the immutable request. It never runs the work.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from factory_state.dispatch import DispatchRequest
from factory_state.model import (CONTROLLER_IDENTITY, ROLE_ALLOWED_STATES,
                                 ROLE_IDENTITIES, FactoryStateMachine, Lease, StateError)
from factory_state.scope import SignedScopeStore
from .worker import digest


STATE_ROLES = {
    'SPECIFICATION': 'product_spec_author',
    'SPEC_REVIEW': 'product_spec_reviewer',
    'ARCHITECTURE': 'software_architect',
    'IMPLEMENTATION': 'engineering_agent',
    'INSPECTION': 'independent_inspector',
    'QA': 'qa_engineer',
    'SECURITY_REVIEW': 'deep_security_reviewer',
}
REVIEWERS = {'independent_inspector_service', 'product_spec_reviewer_service'}


@dataclass(frozen=True)
class IntakePlan:
    factory_id: str
    task_id: str
    state: str
    state_version: int
    lease: Lease
    request: DispatchRequest
    capability_payload: dict
    review_payload: dict


class AuthenticatedIntakeService:
    """Turn exact owner/reviewer signatures into one queued role request."""

    def __init__(self, state_store, ledger, *, key_loader, clock=None):
        self.states, self.ledger = state_store, ledger
        self.key_loader = key_loader
        self.clock = clock or (lambda: datetime.now(timezone.utc))

    def prepare(self, factory_id, task_id, *, role_id, source_commit, objective_id,
                capability_id, contract_bytes, input_bytes, reviewer_identity,
                required_evidence, stop_condition, rationale,
                lease_seconds=900, receipt_seconds=600):
        now = self.clock()
        if (not isinstance(now, datetime) or now.tzinfo is None or now.utcoffset() is None or
                isinstance(lease_seconds, bool) or not 60 <= lease_seconds <= 3600 or
                isinstance(receipt_seconds, bool) or not 60 <= receipt_seconds <= 1800):
            raise StateError('intake timing is invalid')
        state = self.states.load_state(factory_id, task_id)
        if state is None:
            raise StateError('authoritative task state missing')
        if STATE_ROLES.get(state.state) != role_id or state.state not in ROLE_ALLOWED_STATES.get(role_id, set()):
            raise StateError('requested role is not the next Factory stage')
        identity = ROLE_IDENTITIES[role_id]
        if reviewer_identity not in REVIEWERS or reviewer_identity == identity:
            raise StateError('intake requires an independent authenticated reviewer')
        if any(lease.active_at(now) for lease in state.leases):
            raise StateError('task already has active delegated work')
        for value, name in ((required_evidence, 'required evidence'), (stop_condition, 'stop condition'),
                            (rationale, 'review rationale')):
            if not isinstance(value, str) or not value.strip() or len(value) > 2000:
                raise StateError(f'intake {name} is invalid')
        if not isinstance(contract_bytes, bytes) or not isinstance(input_bytes, bytes):
            raise StateError('intake contract and input must be exact bytes')
        seed = '|'.join((factory_id, task_id, str(state.version), state.state, role_id, source_commit,
                         objective_id, capability_id, digest(contract_bytes), digest(input_bytes)))
        lease_id = 'auto-' + hashlib.sha256(seed.encode()).hexdigest()[:24]
        lease = Lease(lease_id, role_id, identity, now + timedelta(seconds=lease_seconds))
        request = DispatchRequest(lease_id, objective_id, capability_id, source_commit,
                                  digest(contract_bytes), digest(input_bytes))
        issued = int(now.timestamp()); expires = issued + receipt_seconds
        capability = {'kind': 'capability', 'factory_id': factory_id, 'objective_id': objective_id,
            'capability_id': capability_id, 'contract_digest': request.contract_digest,
            'owner_identity': 'tim_brydges', 'required_evidence': required_evidence,
            'stop_condition': stop_condition, 'issued_at': issued, 'expires_at': expires}
        review = {'kind': 'scope_review', 'factory_id': factory_id, 'task_id': task_id,
            'binding': self.ledger._binding(request), 'verdict': 'ACCEPTED',
            'reviewer_identity': reviewer_identity, 'rationale': rationale,
            'issued_at': issued, 'expires_at': expires}
        return IntakePlan(factory_id, task_id, state.state, state.version, lease, request,
                          capability, review)

    def activate(self, plan, *, owner_signature, reviewer_signature):
        if not isinstance(plan, IntakePlan):
            raise StateError('authenticated intake requires an exact prepared plan')
        now = self.clock()
        state = self.states.load_state(plan.factory_id, plan.task_id)
        if state is None or state.state != plan.state:
            raise StateError('intake state changed after review preparation')
        expected_role = STATE_ROLES.get(state.state)
        if (expected_role != plan.lease.role_id or
                ROLE_IDENTITIES.get(expected_role) != plan.lease.authoritative_identity or
                plan.request.lease_id != plan.lease.lease_id):
            raise StateError('reviewed intake plan has an invalid stage or role binding')
        existing = next((item for item in state.leases if item.lease_id == plan.lease.lease_id), None)
        machine = None
        if existing is None:
            if state.version != plan.state_version:
                raise StateError('intake state version changed after review preparation')
            machine = FactoryStateMachine(state)
            reviewed_state = machine.issue_lease(CONTROLLER_IDENTITY, plan.lease,
                expected_version=state.version, now=now)
        else:
            if (existing != plan.lease or state.version != plan.state_version + 1 or
                    not existing.active_at(now)):
                raise StateError('persisted intake lease differs from reviewed plan')
            reviewed_state = state

        scope = SignedScopeStore(self.ledger.table_name, self.ledger.client, self.key_loader(now))
        # Verify every external signature before the first authoritative mutation.
        capability_item = scope._capability_item(reviewed_state, plan.request,
            plan.capability_payload, owner_signature, now=now)
        review_item = scope._review_item(reviewed_state, plan.request,
            plan.review_payload, reviewer_signature, now=now)
        if machine is not None:
            self.states.persist_transition(state, reviewed_state, caller_identity=CONTROLLER_IDENTITY,
                event_id='lease-' + plan.lease.lease_id.removeprefix('auto-'),
                audit_event=machine.last_audit_event)
            current = self.states.load_state(plan.factory_id, plan.task_id)
            if current != reviewed_state:
                raise StateError('issued lease was not durably retained')
        else:
            current = reviewed_state

        scope._write(capability_item)
        scope._write(review_item)
        scope.verify_persisted(current, plan.request, now=now)
        prior = self.ledger.read(current, plan.request)
        if prior is not None:
            if prior.get('status', {}).get('S') not in {'READY', 'STARTED', 'RECEIPT_RECORDED'}:
                raise StateError('queued intake has an unknown durable status')
            return {'status': 'ALREADY_QUEUED', 'lease_id': plan.lease.lease_id,
                    'dispatch_id': prior['dispatch_id']['S']}
        dispatch_id = self.ledger.enqueue(current, plan.request,
            caller_identity=CONTROLLER_IDENTITY, now=now)
        return {'status': 'QUEUED', 'lease_id': plan.lease.lease_id,
                'dispatch_id': dispatch_id, 'model_calls': 0, 'release_dispatched': False}
