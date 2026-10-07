"""Fresh bounded-review-004 provider scope; no credentials, network or signing."""
import base64
from dataclasses import asdict, dataclass
from datetime import datetime

from factory_state.dispatch import DispatchRequest
from factory_state.model import COMMIT_SHA, SHA256_DIGEST, StateError
from factory_state.scope import SignedScopeStore, canonical
from .pilot002_adapter import _cost
from .pilot002_authorization import _exact, _window
from .worker import digest

TASK = 'bounded-review-004'
FACTORY = 'tims-software-factory'
PROVIDERS = {'builder': ('openai', 'gpt-5.6-sol'),
             'inspector': ('bedrock', 'global.anthropic.claude-sonnet-4-5-20250929-v1:0'),
             'qa': ('google', 'gemini-3.7-flash')}
ROLE_CAPS = {'builder':250000, 'inspector':175000, 'qa':75000}
RUN_CAP = sum(ROLE_CAPS.values())


@dataclass(frozen=True)
class ProviderScope:
    role: str
    request: DispatchRequest
    candidate_commit: str
    candidate_digest: str
    test_evidence_digest: str
    request_bytes: bytes

    def bindings(self):
        if (type(self.role) is not str or self.role not in PROVIDERS or
                type(self.request) is not DispatchRequest or
                type(self.candidate_commit) is not str or not COMMIT_SHA.fullmatch(self.candidate_commit) or
                any(type(v) is not str or not SHA256_DIGEST.fullmatch(v)
                    for v in (self.candidate_digest, self.test_evidence_digest)) or
                type(self.request_bytes) is not bytes or not 0 < len(self.request_bytes) <= 65536):
            raise StateError('exact fresh provider scope required')
        provider, model = PROVIDERS[self.role]
        return {'factory_id': FACTORY, 'task_id': TASK, 'role': self.role,
            'provider': provider, 'model_id': model, 'dispatch_request': asdict(self.request),
            'candidate_commit': self.candidate_commit, 'candidate_digest': self.candidate_digest,
            'test_evidence_digest': self.test_evidence_digest, 'request_digest': digest(self.request_bytes)}


@dataclass(frozen=True)
class VerifiedAllowance:
    """Internal verification result, never accepted from an event or model."""
    role: str
    allowance_digest: str
    scope_digest: str
    maximum_cost_micro_usd: int
    expires_at: int


def validate_unsigned(payload, *, scope, pricing, readiness, now):
    if (type(scope) is not ProviderScope or type(now) is not datetime or
            now.tzinfo is None or now.utcoffset() is None):
        raise StateError('deployment-owned scope and aware clock required')
    binding = scope.bindings()
    price_expected = {'kind': 'bounded_review004_rate_qualification', **binding,
        'currency': 'USD', 'complete_request_bound_qualified': True,
        'standard_text_only_no_cache_rates': True, 'output_token_bound': 4096}
    extra = {'input_token_bound', 'input_micro_usd_per_million', 'output_micro_usd_per_million',
             'issued_at', 'expires_at', 'evidence_digest'}
    if (not _exact(pricing, price_expected, extra) or not _window(pricing, now, 86400) or
            type(pricing['input_token_bound']) is not int or not 0 < pricing['input_token_bound'] <= 32768 or
            any(type(pricing[k]) is not int or not 0 <= pricing[k] <= 1000000000
                for k in ('input_micro_usd_per_million', 'output_micro_usd_per_million')) or
            type(pricing['evidence_digest']) is not str or not SHA256_DIGEST.fullmatch(pricing['evidence_digest'])):
        raise StateError('fresh exact-request pricing required')
    maximum = _cost(pricing['input_token_bound'], 4096, pricing)
    if not 0 < maximum <= ROLE_CAPS[scope.role]:
        raise StateError('provider request exceeds reserved cap')
    ready_expected = {'kind': 'bounded_review004_provider_readiness', **binding,
        'credential_route_verified': True, 'model_metadata_verified': True,
        'repository_binding_verified': True, 'single_attempt_failure_risk_accepted': True}
    if (not _exact(readiness, ready_expected, {'issued_at', 'expires_at', 'evidence_digest'}) or
            not _window(readiness, now, 3600) or type(readiness['evidence_digest']) is not str or
            not SHA256_DIGEST.fullmatch(readiness['evidence_digest'])):
        raise StateError('fresh exact-route readiness required')
    expected = {'kind': 'bounded_review004_provider_allowance', 'owner_identity': 'tim_brydges',
        **binding, 'pricing_digest': digest(canonical(pricing)),
        'readiness_digest': digest(canonical(readiness)), 'reserved_micro_usd': ROLE_CAPS[scope.role],
        'run_reserved_micro_usd': RUN_CAP, 'aggregate_ceiling_micro_usd': 3250000,
        'maximum_provider_calls': 1, 'retries': 0, 'production_release_authorized': False}
    if (not _exact(payload, expected, {'issued_at', 'expires_at'}) or not _window(payload, now, 3600) or
            payload['expires_at'] > min(pricing['expires_at'], readiness['expires_at'])):
        raise StateError('fresh owner scope, fixed reservation or expiry differs')
    return VerifiedAllowance(scope.role, digest(canonical(payload)), digest(canonical(binding)),
                             maximum, payload['expires_at'])


def verify(envelope, *, trusted_keys, **context):
    if (type(envelope) is not dict or set(envelope) != {'payload', 'signature_base64'} or
            type(envelope['signature_base64']) is not str or len(envelope['signature_base64']) != 88):
        raise StateError('signed fresh provider allowance required')
    grant = validate_unsigned(envelope['payload'], **context)
    try:
        signature = base64.b64decode(envelope['signature_base64'], validate=True)
    except (TypeError, ValueError):
        raise StateError('provider allowance signature encoding invalid') from None
    SignedScopeStore('unused', None, trusted_keys)._verify(
        envelope['payload'], signature, 'tim_brydges', context['now'])
    return grant
