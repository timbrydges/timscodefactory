"""Atomic spending hold plus one-attempt claim; not an authorization verifier.

No live caller is wired. A future broker must authenticate owner approval and
validate pricing, request limits and scope before invoking this primitive.
"""
import hashlib
import re
from datetime import datetime, timezone

from factory_state.model import StateError
from .google_qa_boundary import GoogleQaAttemptStore, KEY, TABLE


class GoogleQaReservedAttemptStore(GoogleQaAttemptStore):
    def begin(self, *, request_bytes, approval_digest, source_commit,
              reserved_micro_usd, approved_cap_micro_usd, pricing_digest,
              approval_expires_at, pricing_expires_at, now):
        """Store hold and claim in one conditional write; never recycle either."""
        hashes = (approval_digest, pricing_digest)
        times = (approval_expires_at, pricing_expires_at, now)
        if (not isinstance(request_bytes, bytes) or not 0 < len(request_bytes) <= 32768 or
                any(not isinstance(h, str) or not re.fullmatch(r'sha256:[0-9a-f]{64}', h)
                    for h in hashes) or not isinstance(source_commit, str) or
                not re.fullmatch('[0-9a-f]{40}', source_commit) or
                type(reserved_micro_usd) is not int or type(approved_cap_micro_usd) is not int or
                not 0 < reserved_micro_usd <= approved_cap_micro_usd <= 1000000 or
                any(not isinstance(t, datetime) or t.tzinfo is None or t.utcoffset() is None
                    for t in times)):
            raise StateError('Google reservation binding invalid')
        if now >= min(approval_expires_at, pricing_expires_at):
            raise StateError('Google reservation approval or pricing expired')
        digest = 'sha256:' + hashlib.sha256(request_bytes).hexdigest()
        item = {**KEY, 'status': {'S': 'STARTED'}, 'request_digest': {'S': digest},
            'approval_digest': {'S': approval_digest}, 'source_commit': {'S': source_commit},
            'pricing_digest': {'S': pricing_digest}, 'reservation_status': {'S': 'HELD'},
            'reserved_micro_usd': {'N': str(reserved_micro_usd)},
            'approved_cap_micro_usd': {'N': str(approved_cap_micro_usd)},
            'claimed_at': {'S': now.astimezone(timezone.utc).isoformat()},
            'approval_expires_at': {'S': approval_expires_at.astimezone(timezone.utc).isoformat()},
            'pricing_expires_at': {'S': pricing_expires_at.astimezone(timezone.utc).isoformat()}}
        try:
            self.client.put_item(TableName=TABLE, Item=item,
                ConditionExpression='attribute_not_exists(PK) AND attribute_not_exists(SK)')
        except Exception:
            raise StateError('Google reservation exists or is uncertain; reconcile without retry') from None
        return digest
