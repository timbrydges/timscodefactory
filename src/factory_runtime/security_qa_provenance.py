"""Authenticate consumed QA provenance, never renew historical dispatch authority."""
from dataclasses import replace
from datetime import datetime, timezone

from factory_state.dispatch import DispatchRequest
from factory_state.model import StateError
from factory_state.scope import SignedScopeStore
from .progression import _strict_json, _decode
from .review_verdict import ReviewBinding, BoundReviewValidator
from .security_verdict import SecurityReviewBinding
from .worker import digest
from factory_state.scope import canonical


class ConsumedQAProvenance:
    """Read-only prerequisite for a fresh security backend.

    Deployment authenticates the historical key loader and exact QA binding.
    The prior result is verified at issuance only as consumed provenance. Current
    security scope, leases, pricing and fresh tests remain independently required.
    No synthetic proof files or historical acceptance overrides are loaded.
    """
    def __init__(self, *, binding, qa_binding, qa_request, states, ledger,
                 historical_key_loader, clock):
        if (type(binding) is not SecurityReviewBinding or type(qa_binding) is not ReviewBinding or
                qa_binding.role_id != 'qa_engineer' or type(qa_request) is not DispatchRequest or
                not callable(historical_key_loader) or not callable(clock)):
            raise StateError('Deployment-owned QA provenance configuration required')
        binding.validate(); qa_binding.validate()
        shared = ('factory_id', 'task_id', 'contract_digest', 'candidate_commit', 'candidate_digest', 'allowed_paths')
        if (any(getattr(binding.qa, key) != getattr(qa_binding, key) for key in shared) or
                (qa_request.source_commit, qa_request.contract_digest, qa_request.input_digest) !=
                (qa_binding.source_commit, qa_binding.contract_digest, qa_binding.input_digest)):
            raise StateError('QA prerequisite candidate or dispatch differs')
        self.binding, self.qa_binding, self.request = binding, qa_binding, qa_request
        self.states, self.ledger = states, ledger
        self.keys, self.clock = historical_key_loader, clock

    def __call__(self, binding):
        if binding != self.binding:
            return False
        try:
            now = self.clock(); q = self.qa_binding
            if not isinstance(now, datetime) or now.tzinfo is None or now.utcoffset() is None:
                return False
            state = self.states.load_state(q.factory_id, q.task_id)
            if state is None or (state.factory_id, state.task_id, state.state) != (q.factory_id, q.task_id, 'SECURITY_REVIEW'):
                return False
            evidence_id = 'result-' + binding.qa_result_digest.removeprefix('sha256:')
            if evidence_id not in state.consumed_evidence_ids:
                return False
            row = self.ledger.read(state, self.request)
            if row is None or row.get('status') != {'S':'RECEIPT_RECORDED'}:
                return False
            payload = _strict_json(row['result_payload']['S'])
            signature = _decode(row['result_signature']['S'], 64)
            output = _decode(row['result_output']['S'], 32768)
            if (len(signature) != 64 or digest(canonical(payload)) != binding.qa_result_digest or
                    row['receipt_digest'] != {'S':binding.qa_result_digest}):
                return False
            expected = {'kind':'role_result', 'factory_id':q.factory_id, 'task_id':q.task_id,
                'binding':self.ledger._binding(self.request), 'dispatch_id':row['dispatch_id']['S'],
                'producer_identity':'qa_engineer_service', 'output_digest':digest(output)}
            if (set(payload) != set(expected) | {'issued_at','expires_at'} or
                    any(payload.get(k) != v for k,v in expected.items()) or
                    type(payload['issued_at']) is not int or not 0 <= payload['issued_at'] <= now.timestamp()):
                return False
            issued = datetime.fromtimestamp(payload['issued_at'], timezone.utc)
            SignedScopeStore('unused', None, self.keys(issued))._verify(
                payload, signature, 'qa_engineer_service', issued)
            # This checks historical verdict shape and binding only. The consumed
            # transition establishes prior acceptance; current test proof is checked
            # separately by SecurityProviderBackend, never renewed here.
            validator = BoundReviewValidator(q, lambda *args: True)
            return validator(replace(state, state='QA'), self.request, output) is True
        except (StateError, ValueError, TypeError, KeyError, AttributeError, OverflowError):
            return False
