"""Unwired recovery accounting; not a signer, live allowance or provider client."""
import hashlib
import re
from datetime import datetime, timedelta, timezone

from factory_state.model import StateError

TABLE = 'tims-factory-qa-recovery-001-attempts'
PK = 'RECOVERY#001#TASK#safe-workspace-fingerprint-001#ROLE#qa'
CANDIDATE = '09c789a902377cb095c20abae89459c4cec3e89e'
SCOPE_FILE = 'factory/autonomy/qa-recovery-001-scope.json'
SCOPE_SHA256 = 'd69dadb93f7d92ab26facbaa7741dcef1f987d4ccf91fa2bfb8c125efba23bd6'
CAP = 250000
REQUEST_DIGEST = 'sha256:6891cd13c024807b3d02ff30e6f5872207deeeb38f4c7fd23b7ec825c6ef4ed7'


def digest(value):
    return 'sha256:'+hashlib.sha256(value).hexdigest()


def _digest(value):
    return type(value) is str and re.fullmatch(r'sha256:[0-9a-f]{64}', value)


class RecoveryAttemptStore:
    """One fixed permanent record, with no API capable of modifying Pilot 002.

    A future owner-authorized caller must verify the exact signed allowance,
    request, pricing and readiness before begin. enabled alone is not authority.
    The injected client must use one SDK attempt; this class never retries.
    """
    def __init__(self, client, *, root, enabled=False):
        self.client = client
        self.enabled = enabled is True
        with (root/SCOPE_FILE).open('rb') as stream:
            raw = stream.read(65537)
        if len(raw)>65536 or hashlib.sha256(raw).hexdigest()!=SCOPE_SHA256:
            raise StateError('Recovery scope changed')

    def _enabled(self):
        if not self.enabled:
            raise StateError('Recovery accounting disabled')

    def begin(self, *, candidate_commit, source_commit, request_bytes,
              approval_digest, pricing_digest, maximum_cost_micro_usd,
              now, approval_expires_at, pricing_expires_at):
        self._enabled()
        times = (now, approval_expires_at, pricing_expires_at)
        if (candidate_commit!=CANDIDATE or type(source_commit) is not str or
                not re.fullmatch('[0-9a-f]{40}', source_commit) or
                type(request_bytes) is not bytes or not 0<len(request_bytes)<=65536 or
                not _digest(approval_digest) or not _digest(pricing_digest) or
                type(maximum_cost_micro_usd) is not int or maximum_cost_micro_usd!=0 or
                any(not isinstance(t,datetime) or t.tzinfo is None or t.utcoffset() is None for t in times)):
            raise StateError('Recovery claim binding invalid')
        if not now<min(approval_expires_at,pricing_expires_at) or max(approval_expires_at,pricing_expires_at)>now+timedelta(seconds=300):
            raise StateError('Recovery claim expired or window exceeds bound')
        request_digest = digest(request_bytes)
        if request_digest!=REQUEST_DIGEST:raise StateError('QA recovery request changed')
        item = {'PK':{'S':PK}, 'status':{'S':'STARTED'}, 'reservation_status':{'S':'HELD'},
            'reserved_micro_usd':{'N':str(CAP)}, 'scope_digest':{'S':'sha256:'+SCOPE_SHA256},
            'candidate_commit':{'S':CANDIDATE}, 'source_commit':{'S':source_commit},
            'request_digest':{'S':request_digest}, 'approval_digest':{'S':approval_digest},
            'pricing_digest':{'S':pricing_digest}, 'maximum_cost_micro_usd':{'N':str(maximum_cost_micro_usd)},
            'claimed_at':{'S':now.astimezone(timezone.utc).isoformat()},
            'approval_expires_at':{'S':approval_expires_at.astimezone(timezone.utc).isoformat()},
            'pricing_expires_at':{'S':pricing_expires_at.astimezone(timezone.utc).isoformat()}}
        try:
            self.client.put_item(TableName=TABLE,Item=item,ConditionExpression='attribute_not_exists(PK)')
        except Exception:
            raise StateError('Recovery attempt exists or is uncertain; no retry') from None
        return request_digest

    def complete(self, *, request_digest, approval_digest, output_bytes, actual_micro_usd):
        self._enabled()
        if (not _digest(request_digest) or not _digest(approval_digest) or
                type(output_bytes) is not bytes or not 0<len(output_bytes)<=65536 or
                type(actual_micro_usd) is not int or actual_micro_usd!=0):
            raise StateError('Recovery completion invalid; retain hold')
        try:
            self.client.update_item(TableName=TABLE,Key={'PK':{'S':PK}},
                ConditionExpression='#s = :started AND request_digest = :request AND approval_digest = :approval AND scope_digest = :scope AND reservation_status = :held AND reserved_micro_usd = :cap AND maximum_cost_micro_usd >= :actual',
                UpdateExpression='SET #s = :complete, output_digest = :output, actual_micro_usd = :actual',
                ExpressionAttributeNames={'#s':'status'},ExpressionAttributeValues={
                    ':started':{'S':'STARTED'},':complete':{'S':'COMPLETE'},':request':{'S':request_digest},
                    ':approval':{'S':approval_digest},':scope':{'S':'sha256:'+SCOPE_SHA256},
                    ':held':{'S':'HELD'},':cap':{'N':str(CAP)},':actual':{'N':str(actual_micro_usd)},
                    ':output':{'S':digest(output_bytes)}})
        except Exception:
            raise StateError('Recovery completion uncertain; retain hold and never repeat provider call') from None
