"""Disabled security backend with fresh authority and permanent send claims."""
import copy
from factory_state.model import CONTROLLER_IDENTITY, FactoryStateMachine, StateError
from factory_state.scope import SignedScopeStore
from .pilot002_adapter import _cost
from .review_provider_backend import BoundedProviderFailure
from .review_verdict import PinnedPythonTestEvidence
from .security_provider_claims import SecurityProviderClaims
from .security_provider_protocol import PreparedSecurityRequest, parse_response
from .security_provider_scope import verify
from .security_provider_transport import SecurityProviderTransport


class SecurityProviderBackend:
    def __init__(self, *, prepared, envelope, pricing, readiness, states, ledger,
                 claims, key_loader, test_evidence, verify_prerequisites, clock,
                 load_credential=None, enabled=False):
        if (type(prepared) is not PreparedSecurityRequest or type(claims) is not SecurityProviderClaims or
                type(test_evidence) is not PinnedPythonTestEvidence or type(enabled) is not bool or
                not callable(verify_prerequisites) or
                (load_credential is not None and not callable(load_credential))):
            raise StateError('Deployment-owned security backend configuration required')
        prepared.validate()
        if test_evidence.binding != prepared.scope.binding.qa:
            raise StateError('Security test evidence differs from exact deployment')
        self.prepared, self.states, self.ledger, self.claims = prepared, states, ledger, claims
        self.envelope, self.pricing, self.readiness = copy.deepcopy((envelope, pricing, readiness))
        self.key_loader, self.evidence, self.clock = key_loader, test_evidence, clock
        self.verify_prerequisites = verify_prerequisites
        self.load_credential, self.enabled = load_credential, enabled
        self.worker_id = 'bounded-security-controller'

    def check_activation(self, state, request, *, now):
        if not self.enabled:
            raise StateError('Security provider backend disabled')
        scope = self.prepared.scope; q = scope.binding.qa
        if ((state.factory_id, state.task_id, state.state) !=
                (q.factory_id, q.task_id, 'SECURITY_REVIEW') or request != scope.request or
                self.states.load_state(q.factory_id, q.task_id) != state):
            raise StateError('Security task or request changed')
        FactoryStateMachine(state).assert_dispatch_allowed(CONTROLLER_IDENTITY, request.lease_id, now=now)
        lease = next(l for l in state.leases if l.lease_id == request.lease_id)
        if (lease.role_id, lease.authoritative_identity) != ('deep_security_reviewer', 'deep_security_reviewer_service'):
            raise StateError('Security lease identity differs')
        keys = self.key_loader(now)
        SignedScopeStore(self.ledger.table_name, self.ledger.client, keys).verify_persisted(state, request, now=now)
        if (self.evidence(q.candidate_commit, q.candidate_digest, q.test_evidence_digest) is not True or
                self.verify_prerequisites(scope.binding) is not True):
            raise StateError('Security proof or prerequisite authentication failed')
        return verify(self.envelope, scope=scope, pricing=self.pricing, readiness=self.readiness,
                      trusted_keys=keys, now=now)

    def _started(self, state, request, dispatch_id, now):
        self.ledger.assert_started(state, request, worker_id=self.worker_id, now=now)
        row = self.ledger.read(state, request)
        if row is None or row.get('dispatch_id') != {'S': dispatch_id}:
            raise StateError('Security send requires exact claimed dispatch')

    def reserve(self, state, request, *, dispatch_id, now):
        grant = self.check_activation(state, request, now=now)
        self._started(state, request, dispatch_id, now)
        return self.claims.hold(grant, dispatch_id, now=now)

    def execute(self, state, request, *, dispatch_id, input_bytes):
        if self.load_credential is None:
            raise StateError('Security controller guard cannot load credentials')
        if type(input_bytes) is not bytes or input_bytes != self.prepared.input_bytes:
            raise StateError('Security input differs from exact job')
        phase = 'authorization'; credential = None
        try:
            now = self.clock(); grant = self.check_activation(state, request, now=now)
            self._started(state, request, dispatch_id, now)
            phase = 'send claim'
            self.claims.begin_send(grant, dispatch_id, now=now)
            phase = 'credential loading'
            credential = self.load_credential()
            now = self.clock(); self.check_activation(state, request, now=now)
            self._started(state, request, dispatch_id, now)
            phase = 'provider transport'
            raw = SecurityProviderTransport(self.prepared, enabled=True).send_once(
                request_bytes=self.prepared.scope.request_bytes, credential=credential,
                expected_request_digest=self.prepared.scope.bindings()['request_digest'])
            credential = None
            phase = 'response validation'
            output, usage = parse_response(raw, self.prepared)
            actual = _cost(usage['input_tokens'], usage['output_tokens_including_reasoning'], self.pricing)
            if usage['input_tokens'] > self.pricing['input_token_bound'] or actual > grant.maximum_cost_micro_usd:
                raise StateError('Security usage exceeds qualified cap')
            phase = 'completion'
            now = self.clock(); self.check_activation(state, request, now=now)
            self.claims.complete(grant, dispatch_id, now=now, output=output, actual_micro_usd=actual)
            return output
        except Exception as error:
            raise BoundedProviderFailure(phase, error) from None
        finally:
            credential = None
