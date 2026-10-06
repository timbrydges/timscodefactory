"""Disabled role backend: fresh scope, persisted task, hold, send once, bounded cost."""
import copy
from factory_state.model import CONTROLLER_IDENTITY, FactoryStateMachine, StateError
from factory_state.scope import SignedScopeStore
from .cloud_roles import ROLE_IDS, ROLE_IDENTITIES
from .pilot002_adapter import _cost
from .pilot002_transport import ProviderHTTPStatusError, ProviderTimeoutError
from .review_provider_claims import ReviewProviderClaims
from .review_provider_protocol import PreparedProviderRequest, parse_response
from .review_provider_scope import FACTORY, TASK, verify
from .review_provider_transport import ReviewProviderTransport
from .review_verdict import PinnedPythonTestEvidence


class BoundedProviderFailure(StateError):
    """Only allowlisted phase/category and numeric status cross the log boundary."""
    def __init__(self, phase, error=None):
        self.phase = phase if phase in ('authorization', 'send claim', 'credential loading',
            'provider transport', 'response validation', 'completion') else 'unknown'
        self.http_status = None
        self.category = 'unknown'
        if self.phase == 'provider transport':
            if type(error) is ProviderHTTPStatusError:
                status = error.http_status
                if type(status) is int and 300 <= status <= 599:
                    self.http_status = status
                    self.category = 'http '+str(status)
            elif type(error) is ProviderTimeoutError:
                self.category = 'timeout'
        super().__init__('bounded provider stopped at '+self.phase+' ('+self.category+
            '); retain hold and reconcile without retry')


class ReviewProviderBackend:
    """Deployment owns every dependency. A controller guard has no credential loader.

    RoleExecutionService also guards scope/state and signs the resulting bytes. This
    backend does not sign results or progress a gate; rejected reviews remain rejected.
    """
    def __init__(self, *, prepared, envelope, pricing, readiness, states, ledger,
                 claims, key_loader, test_evidence, clock, load_credential=None, enabled=False):
        if (type(prepared) is not PreparedProviderRequest or type(claims) is not ReviewProviderClaims or
                type(test_evidence) is not PinnedPythonTestEvidence or type(enabled) is not bool or
                (load_credential is not None and not callable(load_credential))):
            raise StateError('deployment-owned provider backend configuration required')
        prepared.validate()
        scope = prepared.scope; b = test_evidence.binding
        expected = (FACTORY, TASK, scope.request.source_commit, scope.request.contract_digest,
                    scope.candidate_commit, scope.candidate_digest, scope.test_evidence_digest)
        if (b.factory_id,b.task_id,b.source_commit,b.contract_digest,b.candidate_commit,
                b.candidate_digest,b.test_evidence_digest) != expected:
            raise StateError('provider test evidence differs from exact deployment')
        self.prepared, self.states, self.ledger, self.claims = prepared, states, ledger, claims
        self.envelope, self.pricing, self.readiness = copy.deepcopy((envelope,pricing,readiness))
        self.key_loader, self.evidence, self.clock = key_loader, test_evidence, clock
        self.load_credential, self.enabled = load_credential, enabled
        self.worker_id = 'bounded-review-controller'

    def check_activation(self, state, request, *, now):
        if not self.enabled:
            raise StateError('fresh review provider backend disabled')
        scope = self.prepared.scope
        if (state.factory_id,state.task_id) != (FACTORY,TASK) or request != scope.request:
            raise StateError('provider task or request differs from signed scope')
        current = self.states.load_state(FACTORY,TASK)
        if current != state:
            raise StateError('provider task changed; stop before send')
        FactoryStateMachine(state).assert_dispatch_allowed(CONTROLLER_IDENTITY,request.lease_id,now=now)
        lease = next(l for l in state.leases if l.lease_id == request.lease_id)
        if (lease.role_id,lease.authoritative_identity) != (ROLE_IDS[scope.role],ROLE_IDENTITIES[scope.role]):
            raise StateError('provider role differs from authoritative lease')
        keys = self.key_loader(now)
        SignedScopeStore(self.ledger.table_name,self.ledger.client,keys).verify_persisted(state,request,now=now)
        b = self.evidence.binding
        if self.evidence(b.candidate_commit,b.candidate_digest,b.test_evidence_digest) is not True:
            raise StateError('provider independent test evidence expired or invalid')
        return verify(self.envelope,scope=scope,pricing=self.pricing,readiness=self.readiness,
                      trusted_keys=keys,now=now)

    def _started(self,state,request,dispatch_id,now):
        self.ledger.assert_started(state,request,worker_id=self.worker_id,now=now)
        row = self.ledger.read(state,request)
        if row is None or row.get('dispatch_id') != {'S':dispatch_id}:
            raise StateError('provider send requires the exact claimed dispatch')

    def reserve(self,state,request,*,dispatch_id,now):
        grant = self.check_activation(state,request,now=now)
        self._started(state,request,dispatch_id,now)
        return self.claims.hold(grant,dispatch_id,now=now)

    def execute(self,state,request,*,dispatch_id,input_bytes):
        if self.load_credential is None:
            raise StateError('controller guard cannot load credentials or execute providers')
        if type(input_bytes) is not bytes or input_bytes != self.prepared.input_bytes:
            raise StateError('provider execution input differs from exact job')
        phase = 'authorization'; credential = None
        try:
            now = self.clock(); grant = self.check_activation(state,request,now=now)
            self._started(state,request,dispatch_id,now)
            phase = 'send claim'
            self.claims.begin_send(grant,dispatch_id,now=now)
            phase = 'credential loading'
            credential = self.load_credential()
            now = self.clock(); self.check_activation(state,request,now=now)
            self._started(state,request,dispatch_id,now)
            phase = 'provider transport'
            raw = ReviewProviderTransport(self.prepared,enabled=True).send_once(
                request_bytes=self.prepared.scope.request_bytes,credential=credential,
                expected_request_digest=self.prepared.scope.bindings()['request_digest'])
            credential = None
            phase = 'response validation'
            output,usage = parse_response(raw,self.prepared)
            actual = _cost(usage['input_tokens'],usage['output_tokens_including_reasoning'],self.pricing)
            if usage['input_tokens'] > self.pricing['input_token_bound'] or actual > grant.maximum_cost_micro_usd:
                raise StateError('observed usage exceeds exact qualified cap')
            phase = 'completion'
            now = self.clock(); self.check_activation(state,request,now=now)
            self.claims.complete(grant,dispatch_id,now=now,output=output,actual_micro_usd=actual)
            return output
        except Exception as error:
            raise BoundedProviderFailure(phase, error) from None
        finally:
            credential = None
