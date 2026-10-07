"""Separate permanent security hold; never reset, release or reuse review claims.

Only a privileged backend may supply a freshly verified security allowance.
The inherited conditional-write machinery uses this fixed security item only.
"""
from datetime import datetime
import re

from factory_state.model import SHA256_DIGEST, StateError
from .review_provider_claims import ReviewProviderClaims
from .security_provider_scope import CLAIM_KEY, RESERVATION, VerifiedSecurityAllowance


class SecurityProviderClaims(ReviewProviderClaims):
    def _item(self, grant, dispatch_id, now):
        if (type(grant) is not VerifiedSecurityAllowance or
                any(type(value) is not str or not SHA256_DIGEST.fullmatch(value)
                    for value in (grant.allowance_digest, grant.scope_digest)) or
                type(grant.maximum_cost_micro_usd) is not int or
                not 0 < grant.maximum_cost_micro_usd <= RESERVATION or
                type(dispatch_id) is not str or not re.fullmatch('[0-9a-f]{64}', dispatch_id) or
                type(now) is not datetime or now.tzinfo is None or now.utcoffset() is None or
                type(grant.expires_at) is not int or
                not now.timestamp() < grant.expires_at <= now.timestamp()+3600):
            raise StateError('Fresh verified security claim binding required')
        return {'PK': {'S': CLAIM_KEY}, 'status': {'S': 'RESERVED'},
            'task_id': {'S': 'bounded-review-004'}, 'role': {'S': 'security'},
            'dispatch_id': {'S': dispatch_id},
            'allowance_digest': {'S': grant.allowance_digest},
            'scope_digest': {'S': grant.scope_digest},
            'maximum_cost_micro_usd': {'N': str(grant.maximum_cost_micro_usd)},
            'expires_at': {'N': str(grant.expires_at)}, 'reservation_status': {'S': 'HELD'},
            'reserved_micro_usd': {'N': str(RESERVATION)}}

    def complete(self, grant, dispatch_id, *, now, output, actual_micro_usd):
        if (type(output) is not bytes or not 0 < len(output) <= 32768 or
                type(grant) is not VerifiedSecurityAllowance or
                type(actual_micro_usd) is not int or
                not 0 <= actual_micro_usd <= grant.maximum_cost_micro_usd):
            raise StateError('Security result or cost invalid; retain hold')
        self._update(grant, dispatch_id, now, previous='STARTED', following='COMPLETE',
                     output=output, cost=actual_micro_usd)
