"""Owner-authorized, model-free import of the immutable Inspector 014 verdict.

The import lease is a controller reconciliation record, not a claim that the
Inspector signed a new lease or a scope/dispatch authorization. Only the exact
reviewed candidate and baseline can advance, through the normal state machine.
"""
import base64
import hashlib
import json
from dataclasses import replace
from datetime import datetime, timezone

from factory_state.dynamodb import DynamoDBStateStore
from factory_state.model import CONTROLLER_IDENTITY, Evidence, FactoryStateMachine, Lease, StateError
from factory_state.scope import SignedScopeStore, canonical
from factory_state.signers import load_trusted_signers
from .implementation_inspector import ACTIVATION, CANDIDATE, CONTRACT, EXPIRY, FILES, PACKET_SHA, digest

ENABLED = 'FACTORY_INSPECTION_COMPLETION_ENABLED'
AUTHORIZATION = 'inspector-014-completion-authorization'
REVIEW = 'factory/evidence/inspector-014-signed-implementation-review-2026-10-02.json'
REVIEW_SHA = '23f8f990ac44612663dc056c8f318dbe412fcac3f1220367e02b79efc7d220c7'
BASELINE = 'factory/evidence/inspector-014-completion-baseline.json'
BASELINE_SHA = '9229d33c2fd6b866e03c3f3ff7a7fd558d784bf39678f3da1c9bad6c7c41be20'
LEASE_ID = 'inspection-import-014'


def validate_event(event, commit):
    if event != {'kind': 'complete_implementation_inspection', 'source_commit': commit,
                 'authorization_id': AUTHORIZATION, 'candidate_commit': CANDIDATE}:
        raise StateError('inspection completion event differs from exact approval')


def validate_bundle(root, now):
    approval = json.loads((root / ('factory/evidence/' + AUTHORIZATION + '.json')).read_bytes())
    expected = {'owner_identity': 'tim_brydges', 'authorization_id': AUTHORIZATION,
        'candidate_commit': CANDIDATE, 'review_sha256': REVIEW_SHA,
        'baseline_sha256': BASELINE_SHA, 'from_state': 'INSPECTION', 'from_version': 10,
        'target_state': 'QA', 'maximum_model_calls': 0, 'schedule_enabled': False,
        'production_release_authorized': False, 'expires_at': EXPIRY}
    if (any(type(approval.get(k)) is not type(v) or approval[k] != v for k, v in expected.items()) or
            not datetime.fromisoformat(approval['authorized_at']) <= now < datetime.fromisoformat(EXPIRY)):
        raise StateError('inspection completion approval differs or expired')
    baseline = DynamoDBStateStore._deserialize_payload((root / BASELINE).read_text())
    if hashlib.sha256(canonical(DynamoDBStateStore._serialize_state(baseline))).hexdigest() != BASELINE_SHA:
        raise StateError('inspection completion baseline differs')
    raw = (root / REVIEW).read_bytes()
    if hashlib.sha256(raw).hexdigest() != REVIEW_SHA:
        raise StateError('inspection completion review bytes differ')
    review = json.loads(raw)
    payload = review['payload']
    expected_payload = {'kind': 'role_result',
        'purpose': 'independent-implementation-review-evidence-only',
        'producer_identity': 'independent_inspector_service', 'activation_id': ACTIVATION,
        'source_commit': 'd026f252e37a7879fb5552e1aafca197dbf54afa',
        'candidate_commit': CANDIDATE, 'packet_digest': 'sha256:' + PACKET_SHA,
        'contract_digest': CONTRACT, 'files_sha256': FILES, 'verdict': 'ACCEPTED',
        'model_calls': 1, 'provider_calls_remaining': 0, 'operational_execution_enabled': False,
        'production_release_authorized': False,
        'assessment_digest': digest(canonical(review['assessment'])),
        'independent_tests_digest': digest(canonical(review['independent_tests'])),
        'expires_at': int(datetime.fromisoformat(EXPIRY).timestamp())}
    if (set(payload) != set(expected_payload) | {'issued_at'} or
            any(type(payload.get(k)) is not type(v) or payload[k] != v for k, v in expected_payload.items()) or
            review['status'] != 'IMPLEMENTATION_REVIEW_ACCEPTED' or
            review['independent_tests']['tests_passed'] != 11 or
            review['independent_tests']['exit_code'] != 0):
        raise StateError('inspection result is not the approved accepted verdict')
    keys = load_trusted_signers(root / 'factory/profiles/scope-signers.json', now=now)
    SignedScopeStore('unused', None, keys)._verify(payload,
        base64.b64decode(review['signature_base64'], validate=True),
        'independent_inspector_service', now)
    return baseline, payload


class InspectionCompletion:
    def __init__(self, root, states, *, clock):
        self.root, self.states, self.clock = root, states, clock

    def _persist(self, before, machine, after):
        # Bind the idempotency token to the exact transaction's timestamp. A
        # failed/unknown write is reconciled by reading state on the next call.
        token = 'import-' + hashlib.sha256(canonical(machine.last_audit_event)).hexdigest()[:29]
        self.states.persist_transition(before, after, caller_identity=CONTROLLER_IDENTITY,
            event_id=token, audit_event=machine.last_audit_event)

    def complete(self):
        now = self.clock()
        baseline, payload = validate_bundle(self.root, now)
        evidence_id = 'inspection-import-' + hashlib.sha256(canonical(payload)).hexdigest()
        lease = Lease(LEASE_ID, 'independent_inspector', 'independent_inspector_service',
                      datetime.fromisoformat(EXPIRY))
        state = self.states.load_state(baseline.factory_id, baseline.task_id)
        if state is None:
            raise StateError('inspection completion task missing')
        imported = replace(baseline, version=11, updated_at=state.updated_at,
                           leases=baseline.leases + (lease,))
        completed = replace(imported, state='QA', version=12,
            leases=tuple(replace(item, revoked=True) for item in imported.leases),
            consumed_evidence_ids=baseline.consumed_evidence_ids | {evidence_id})
        if state == completed:
            return self._result('ALREADY_ADVANCED', state, evidence_id)
        if state == baseline:
            machine = FactoryStateMachine(state)
            after = machine.issue_lease(CONTROLLER_IDENTITY, lease, expected_version=10, now=now)
            self._persist(state, machine, after)
            state = self.states.load_state(baseline.factory_id, baseline.task_id)
            if state != after:
                raise StateError('inspection import lease commit changed; reconcile before continuing')
            imported = after
        if state != imported or not baseline.updated_at <= state.updated_at <= now:
            raise StateError('inspection completion state drift; no reset permitted')
        evidence = Evidence(evidence_id, 'independent_inspector', 'independent_inspector_service',
            baseline.task_id, LEASE_ID, CANDIDATE, digest(canonical(payload)),
            datetime.fromtimestamp(payload['issued_at'], timezone.utc), True)
        machine = FactoryStateMachine(state)
        after = machine.transition(CONTROLLER_IDENTITY, 'QA', expected_version=11,
                                   evidence=(evidence,), now=now)
        self._persist(state, machine, after)
        return self._result('ADVANCED', after, evidence_id)

    @staticmethod
    def _result(status, state, evidence_id):
        return {'status': status, 'state': state.state, 'version': state.version,
            'evidence_id': evidence_id, 'candidate_commit': CANDIDATE, 'model_calls': 0,
            'schedule_enabled': False, 'release_dispatched': False}
