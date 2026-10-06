"""Independent deterministic scope review for the fixed fingerprint exercise.

This reviews permitted work and its evidence/stop link, never provider results.
Deployment authenticates candidate and Docker artifact provenance before use.
"""
import copy
from datetime import datetime, timedelta

from factory_state.dispatch import DynamoDBDispatchStore
from factory_state.model import CONTROLLER_IDENTITY, FactoryStateMachine, StateError
from factory_state.scope import SignedScopeStore, canonical
from .cloud_roles import ROLE_IDS, ROLE_IDENTITIES
from .intake import IntakePlan
from .review_provider_protocol import PreparedProviderRequest
from .review_provider_scope import FACTORY, TASK, PROVIDERS
from .review_signing import _EnrolledSigner
from .review_verdict import PinnedPythonTestEvidence
from .worker import digest

IDENTITY = 'product_spec_reviewer_service'
EVIDENCE = 'Authenticated exact-source Docker proof: 17 fingerprint tests; signed independent role results.'
STOP = 'One attempt per provider, no retries; stop on uncertainty, rejection or stale evidence; stop before SECURITY_REVIEW.'
RATIONALE = 'Fixed fingerprint scope, exact candidate and test proof, owner evidence/stop link, independent role and bounded lease verified.'
STAGES = {'builder': 'IMPLEMENTATION', 'inspector': 'INSPECTION', 'qa': 'QA'}


def contract(*, source_commit, candidate_commit, candidate_digest, test_evidence_digest):
    from factory_state.model import COMMIT_SHA, SHA256_DIGEST
    if (any(type(v) is not str or not COMMIT_SHA.fullmatch(v) for v in (source_commit, candidate_commit)) or
            any(type(v) is not str or not SHA256_DIGEST.fullmatch(v)
                for v in (candidate_digest, test_evidence_digest))):
        raise StateError('fixed contract requires immutable source/candidate/test pins')
    return canonical({'kind': 'bounded_review002_contract', 'factory_id': FACTORY, 'task_id': TASK,
        'objective': 'Reproduce and independently review the pinned fingerprint candidate',
        'source_commit': source_commit, 'candidate_commit': candidate_commit,
        'candidate_digest': candidate_digest, 'test_evidence_digest': test_evidence_digest,
        'allowed_paths': ['fingerprint.py', 'tests/test_fingerprint.py'],
        'providers': {role: list(route) for role, route in PROVIDERS.items()},
        'maximum_calls_per_provider': 1, 'retries': 0, 'role_reserved_micro_usd': 250000,
        'run_reserved_micro_usd': 750000, 'aggregate_ceiling_micro_usd': 3000000,
        'candidate_changes_allowed': False, 'production_release_authorized': False,
        'required_evidence': EVIDENCE, 'stop_condition': STOP})


class FixedScopeReview:
    """All arguments come from an authenticated, independent reviewer deployment.

    The owner capability signature is verified, not inferred from a canary or a
    boolean. No signature, state write, provider call or grant occurs here.
    """
    def __init__(self, *, plan, prepared, contract_bytes, owner_signature,
                 test_evidence, states, key_loader, clock):
        if (type(plan) is not IntakePlan or type(prepared) is not PreparedProviderRequest or
                type(test_evidence) is not PinnedPythonTestEvidence or
                type(contract_bytes) is not bytes or type(owner_signature) is not bytes or
                not callable(key_loader) or not callable(clock)):
            raise StateError('deployment-owned independent scope review required')
        self.plan, self.prepared = copy.deepcopy((plan, prepared))
        self.contract_bytes, self.owner_signature = contract_bytes, owner_signature
        self.evidence, self.states, self.key_loader, self.clock = test_evidence, states, key_loader, clock

    def review(self, *, now):
        if type(now) is not datetime or now.tzinfo is None or now.utcoffset() is None:
            raise StateError('aware scope review time required')
        p, prepared = self.plan, self.prepared
        prepared.validate(); scope = prepared.scope
        expected_contract = contract(source_commit=scope.request.source_commit,
            candidate_commit=scope.candidate_commit, candidate_digest=scope.candidate_digest,
            test_evidence_digest=scope.test_evidence_digest)
        if self.contract_bytes != expected_contract or digest(expected_contract) != scope.request.contract_digest:
            raise StateError('work exceeds the fixed reviewed contract')
        state = self.states.load_state(FACTORY, TASK)
        if (state is None or (state.factory_id, state.task_id, state.state, state.version) !=
                (FACTORY, TASK, STAGES[scope.role], p.state_version) or
                (p.factory_id, p.task_id, p.state) != (FACTORY, TASK, state.state) or
                p.request != scope.request or p.request.objective_id != TASK or
                p.request.capability_id != 'bounded-review-'+scope.role or p.lease.lease_id != p.request.lease_id or
                (p.lease.role_id, p.lease.authoritative_identity) !=
                (ROLE_IDS[scope.role], ROLE_IDENTITIES[scope.role]) or
                p.lease.authoritative_identity == IDENTITY or
                any(lease.active_at(now) for lease in state.leases) or
                not now < p.lease.expires_at <= now + timedelta(minutes=15)):
            raise StateError('scope state, dispatch, independence or lease differs')
        # Validate transition permissions without persisting the proposed lease.
        FactoryStateMachine(state).issue_lease(CONTROLLER_IDENTITY, p.lease,
            expected_version=state.version, now=now)
        cap = p.capability_payload
        if cap.get('required_evidence') != EVIDENCE or cap.get('stop_condition') != STOP:
            raise StateError('owner evidence and stop link differ from fixed policy')
        for receipt in (cap, p.review_payload):
            if (type(receipt.get('issued_at')) is not int or type(receipt.get('expires_at')) is not int or
                    not receipt['issued_at'] <= now.timestamp() < receipt['expires_at'] <= receipt['issued_at'] + 600 or
                    receipt['expires_at'] > p.lease.expires_at.timestamp()):
                raise StateError('scope receipt lifetime exceeds bounded delegation')
        SignedScopeStore('unused', None, self.key_loader(now))._capability_item(
            state, p.request, cap, self.owner_signature, now=now)
        b = self.evidence.binding
        if (self.evidence.test_count != 17 or
                (b.factory_id, b.task_id, b.source_commit, b.contract_digest, b.candidate_commit,
                 b.candidate_digest, b.test_evidence_digest) !=
                (FACTORY, TASK, p.request.source_commit, p.request.contract_digest, scope.candidate_commit,
                 scope.candidate_digest, scope.test_evidence_digest) or
                self.evidence(scope.candidate_commit, scope.candidate_digest, scope.test_evidence_digest) is not True):
            raise StateError('independent pinned test proof differs or expired')
        expected = {'kind': 'scope_review', 'factory_id': FACTORY, 'task_id': TASK,
            'binding': DynamoDBDispatchStore._binding(p.request), 'verdict': 'ACCEPTED',
            'reviewer_identity': IDENTITY, 'rationale': RATIONALE,
            'issued_at': cap['issued_at'], 'expires_at': cap['expires_at']}
        if canonical(p.review_payload) != canonical(expected):
            raise StateError('scope review payload does not express the checked policy')
        return expected


class ReviewScopeSigner(_EnrolledSigner):
    key_bindings = {'spec': 'arn:aws:kms:ca-central-1:666730517561:key/76066708-e1ef-47c9-98fb-f38003c99d30'}
    role_bindings = {'spec': 'tims-factory-signing-spec-reviewer'}
    identities = {'spec': IDENTITY}

    def __init__(self, *, policy, kms, sts, enabled=False):
        if type(policy) is not FixedScopeReview:
            raise StateError('independent fixed-scope policy required')
        self.policy = policy
        super().__init__(role='spec', kms=kms, sts=sts, key_loader=policy.key_loader,
                         clock=policy.clock, enabled=enabled)

    def _check(self, payload, now):
        if type(payload) is not dict or canonical(payload) != canonical(self.policy.review(now=now)):
            raise StateError('only the independently checked scope review can be signed')
