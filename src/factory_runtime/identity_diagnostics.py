"""Fixed non-secret identity failure categories; never retain exception text."""
from .provider_credentials import ProviderCredentialLeaseError

STAGES = frozenset({
    'github_authorization', 'github_environment', 'github_transport',
    'github_http', 'github_payload', 'github_claims', 'github_lifetime',
    'exchange_authorization', 'exchange_subject', 'exchange_transport',
    'exchange_http', 'exchange_response', 'renewal_validation', 'unknown',
})
REASONS = frozenset({
    'validation', 'timeout', 'transport_failure', 'http_error', 'unknown',
    'response_boundary', 'response_clock', 'expected_scopes', 'response_json',
    'response_fields', 'token_type', 'token_encoding', 'scope_format',
    'scope_mismatch', 'scope_read_extra', 'scope_extra', 'scope_missing',
    'lifetime_format', 'issuance_clock', 'expired',
    'subject_expiry',
})

class IdentityFailure(ProviderCredentialLeaseError):
    def __init__(self, stage='unknown', reason='unknown'):
        self.stage = stage if type(stage) is str and stage in STAGES else 'unknown'
        self.reason = reason if type(reason) is str and reason in REASONS else 'unknown'
        super().__init__('Identity failure: ' + self.stage + '/' + self.reason + '; reconcile; do not retry')


def identity_failure(error, stage):
    if type(error) is IdentityFailure:
        return IdentityFailure(error.stage, error.reason)
    reason = 'timeout' if isinstance(error, TimeoutError) else 'validation'
    # Transport failure codes are already sanitized, but enforce our own allowlist.
    code = getattr(error, 'failure_code', None)
    if type(code) is str and code in REASONS:
        reason = code
    return IdentityFailure(stage, reason)


def failure_receipt(error):
    safe = identity_failure(error, 'unknown')
    return {'failure_stage': safe.stage, 'failure_reason': safe.reason}
