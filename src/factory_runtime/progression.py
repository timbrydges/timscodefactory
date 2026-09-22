"""Advance one Factory gate from a retained, independently signed role result.

The progressor is controller-side authority glue. It never invokes a role,
creates scope approval, issues a lease, retries work, or releases production.
"""
from __future__ import annotations

import base64
import hashlib
import json
from datetime import datetime, timezone

from factory_state.model import (CONTROLLER_IDENTITY, Evidence, FactoryStateMachine,
                                 StateError)
from factory_state.scope import SignedScopeStore, canonical
from .worker import digest


ADVANCES = {
    ('SPECIFICATION', 'product_spec_author'): 'SPEC_REVIEW',
    ('SPEC_REVIEW', 'product_spec_reviewer'): 'ARCHITECTURE',
    ('ARCHITECTURE', 'software_architect'): 'IMPLEMENTATION',
    ('IMPLEMENTATION', 'engineering_agent'): 'INSPECTION',
    ('INSPECTION', 'independent_inspector'): 'QA',
    ('QA', 'qa_engineer'): 'SECURITY_REVIEW',
    ('SECURITY_REVIEW', 'deep_security_reviewer'): 'RELEASE_READY',
}
MAX_OUTPUT = 65536


def _strict_json(raw: str) -> dict:
    def unique(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise StateError('duplicate signed result field')
            value[key] = item
        return value
    try:
        value = json.loads(raw, object_pairs_hook=unique)
    except (TypeError, ValueError) as error:
        raise StateError('signed result payload is malformed') from error
    if not isinstance(value, dict):
        raise StateError('signed result payload must be an object')
    return value


def _decode(value: str, maximum: int) -> bytes:
    if not isinstance(value, str) or len(value) > ((maximum + 2) // 3) * 4:
        raise StateError('signed result bytes are malformed')
    try:
        raw = base64.b64decode(value, validate=True)
    except (TypeError, ValueError) as error:
        raise StateError('signed result bytes are malformed') from error
    if len(raw) > maximum:
        raise StateError('signed result bytes exceed limit')
    return raw


class SignedResultProgressor:
    """Persist exactly one evidence-backed transition from a completed dispatch."""

    def __init__(self, state_store, ledger, *, key_loader, clock=None):
        self.states, self.ledger = state_store, ledger
        self.key_loader = key_loader
        self.clock = clock or (lambda: datetime.now(timezone.utc))

    def advance(self, factory_id, task_id, request):
        now = self.clock()
        if not isinstance(now, datetime) or now.tzinfo is None or now.utcoffset() is None:
            raise StateError('progression time must be timezone-aware')
        state = self.states.load_state(factory_id, task_id)
        if state is None:
            raise StateError('authoritative task state missing')
        row = self.ledger.read(state, request)
        if row is None or row.get('status') != {'S': 'RECEIPT_RECORDED'}:
            raise StateError('dispatch has no accepted signed result')
        required = {'receipt_digest', 'result_payload', 'result_signature', 'result_output'}
        if any(name not in row or not isinstance(row[name], dict) or set(row[name]) != {'S'}
               for name in required):
            raise StateError('retained signed result is incomplete')

        payload = _strict_json(row['result_payload']['S'])
        signature = _decode(row['result_signature']['S'], 64)
        output = _decode(row['result_output']['S'], MAX_OUTPUT)
        if len(signature) != 64:
            raise StateError('signed result signature length is invalid')
        receipt = 'sha256:' + hashlib.sha256(canonical(payload)).hexdigest()
        if row['receipt_digest'] != {'S': receipt}:
            raise StateError('retained receipt digest differs from signed payload')
        evidence_id = 'result-' + receipt.removeprefix('sha256:')
        if evidence_id in state.consumed_evidence_ids:
            return {'status': 'ALREADY_ADVANCED', 'state': state.state,
                    'version': state.version, 'evidence_id': evidence_id}

        lease = next((item for item in state.leases if item.lease_id == request.lease_id), None)
        if lease is None:
            raise StateError('result lease is missing from authoritative state')
        target = ADVANCES.get((state.state, lease.role_id))
        if target is None:
            raise StateError('signed result cannot advance this Factory gate')
        expected = {'kind': 'role_result', 'factory_id': state.factory_id, 'task_id': state.task_id,
            'binding': self.ledger._binding(request), 'dispatch_id': row.get('dispatch_id', {}).get('S'),
            'producer_identity': lease.authoritative_identity, 'output_digest': digest(output)}
        if (expected['dispatch_id'] is None or set(payload) != set(expected) | {'issued_at', 'expires_at'} or
                any(payload.get(key) != value for key, value in expected.items())):
            raise StateError('signed result does not match authoritative dispatch')

        scope = SignedScopeStore(self.ledger.table_name, self.ledger.client, self.key_loader(now))
        approvals = scope.verify_persisted(state, request, now=now)
        scope._verify(payload, signature, lease.authoritative_identity, now)
        reviewer = approvals['review'].get('reviewer_identity')
        if not reviewer or reviewer == lease.authoritative_identity:
            raise StateError('accepted result lacks independent scope review')

        evidence = Evidence(evidence_id=evidence_id, producer_role=lease.role_id,
            producer_identity=lease.authoritative_identity, task_id=state.task_id,
            lease_id=lease.lease_id, source_commit=request.source_commit,
            artifact_digest=payload['output_digest'],
            created_at=datetime.fromtimestamp(payload['issued_at'], timezone.utc),
            signature_valid=True, reviewer_identity=reviewer)
        machine = FactoryStateMachine(state)
        after = machine.transition(CONTROLLER_IDENTITY, target, expected_version=state.version,
            evidence=(evidence,), now=now)
        self.states.persist_transition(state, after, caller_identity=CONTROLLER_IDENTITY,
            event_id='result-' + receipt.removeprefix('sha256:')[:29],
            audit_event=machine.last_audit_event)
        return {'status': 'ADVANCED', 'state': after.state, 'version': after.version,
                'evidence_id': evidence_id, 'release_dispatched': False}
