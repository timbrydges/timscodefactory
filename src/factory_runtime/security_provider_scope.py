"""Separate one-call security allowance; no signing, provider IO or claim reuse."""
import base64
from dataclasses import asdict, dataclass
from datetime import datetime

from factory_state.dispatch import DispatchRequest
from factory_state.model import SHA256_DIGEST, StateError
from factory_state.scope import SignedScopeStore, canonical
from .pilot002_adapter import _cost
from .pilot002_authorization import _exact, _window
from .security_verdict import SecurityReviewBinding
from .worker import digest
from .security_policy import policy_digest

RESERVATION = 250000
AGGREGATE_CEILING = 3500000
CLAIM_KEY = 'BOUNDED_SECURITY#004#ROLE#security'
MODEL = 'global.anthropic.claude-sonnet-4-5-20250929-v1:0'


@dataclass(frozen=True)
class SecurityProviderScope:
    binding: SecurityReviewBinding
    request: DispatchRequest
    request_bytes: bytes

    def bindings(self):
        if type(self.binding) is not SecurityReviewBinding or type(self.request) is not DispatchRequest:
            raise StateError('Deployment-owned security binding and dispatch required')
        self.binding.validate()
        b = self.binding
        q = b.qa
        if b.security_scope_digest != policy_digest():
            raise StateError('Security scope must bind the fixed deployment policy')
        if ((q.factory_id, q.task_id) != ('tims-software-factory', 'bounded-review-004') or
                (self.request.source_commit, self.request.contract_digest, self.request.input_digest) !=
                (q.source_commit, q.contract_digest, b.input_digest) or
                type(self.request_bytes) is not bytes or not 0 < len(self.request_bytes) <= 65536):
            raise StateError('Security task, request or candidate binding differs')
        return {'factory_id': q.factory_id, 'task_id': q.task_id, 'role': 'security',
            'provider': 'bedrock', 'model_id': MODEL, 'claim_key': CLAIM_KEY,
            'dispatch_request': asdict(self.request), 'candidate_commit': q.candidate_commit,
            'candidate_digest': q.candidate_digest, 'test_evidence_digest': q.test_evidence_digest,
            'qa_result_digest': b.qa_result_digest, 'security_scope_digest': b.security_scope_digest,
            'request_digest': digest(self.request_bytes)}


@dataclass(frozen=True)
class VerifiedSecurityAllowance:
    allowance_digest: str
    scope_digest: str
    maximum_cost_micro_usd: int
    expires_at: int


def validate_unsigned(payload, *, scope, pricing, readiness, now):
    if (type(scope) is not SecurityProviderScope or type(now) is not datetime or
            now.tzinfo is None or now.utcoffset() is None):
        raise StateError('Exact security scope and aware clock required')
    binding = scope.bindings()
    expected_price = {'kind': 'bounded_security004_rate_qualification', **binding,
        'currency': 'USD', 'complete_request_bound_qualified': True,
        'standard_text_only_no_cache_rates': True, 'output_token_bound': 4096}
    extra = {'input_token_bound', 'input_micro_usd_per_million', 'output_micro_usd_per_million',
             'issued_at', 'expires_at', 'evidence_digest'}
    if (not _exact(pricing, expected_price, extra) or not _window(pricing, now, 86400) or
            type(pricing['input_token_bound']) is not int or not 0 < pricing['input_token_bound'] <= 32768 or
            any(type(pricing[k]) is not int or not 0 <= pricing[k] <= 1000000000
                for k in ('input_micro_usd_per_million', 'output_micro_usd_per_million')) or
            type(pricing['evidence_digest']) is not str or not SHA256_DIGEST.fullmatch(pricing['evidence_digest'])):
        raise StateError('Fresh exact security request pricing required')
    maximum = _cost(pricing['input_token_bound'], 4096, pricing)
    if not 0 < maximum <= RESERVATION:
        raise StateError('Security request exceeds reserved cap')
    expected_ready = {'kind': 'bounded_security004_provider_readiness', **binding,
        'credential_route_verified': True, 'model_metadata_verified': True,
        'repository_binding_verified': True, 'single_attempt_failure_risk_accepted': True}
    if (not _exact(readiness, expected_ready, {'issued_at', 'expires_at', 'evidence_digest'}) or
            not _window(readiness, now, 3600) or type(readiness['evidence_digest']) is not str or
            not SHA256_DIGEST.fullmatch(readiness['evidence_digest'])):
        raise StateError('Fresh exact security route readiness required')
    expected = {'kind': 'bounded_security004_provider_allowance', 'owner_identity': 'tim_brydges',
        **binding, 'pricing_digest': digest(canonical(pricing)),
        'readiness_digest': digest(canonical(readiness)), 'reserved_micro_usd': RESERVATION,
        'aggregate_ceiling_micro_usd': AGGREGATE_CEILING,
        'maximum_provider_calls': 1, 'retries': 0, 'production_release_authorized': False}
    if (not _exact(payload, expected, {'issued_at', 'expires_at'}) or not _window(payload, now, 3600) or
            payload['expires_at'] > min(pricing['expires_at'], readiness['expires_at'])):
        raise StateError('Exact security owner allowance or expiry differs')
    return VerifiedSecurityAllowance(digest(canonical(payload)), digest(canonical(binding)),
                                     maximum, payload['expires_at'])


def verify(envelope, *, trusted_keys, **context):
    if (type(envelope) is not dict or set(envelope) != {'payload', 'signature_base64'} or
            type(envelope['signature_base64']) is not str or len(envelope['signature_base64']) != 88):
        raise StateError('Signed security allowance required')
    grant = validate_unsigned(envelope['payload'], **context)
    try:
        signature = base64.b64decode(envelope['signature_base64'], validate=True)
    except (TypeError, ValueError):
        raise StateError('Security allowance signature encoding invalid') from None
    SignedScopeStore('unused', None, trusted_keys)._verify(
        envelope['payload'], signature, 'tim_brydges', context['now'])
    return grant
