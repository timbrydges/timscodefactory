"""Pilot 002's three non-recyclable holds; no authorization or provider calls.

A future authenticated broker must validate the exact request, fresh pricing,
provider readiness and owner authorization before claiming. Nothing invokes
this primitive from a live handler. Each role can consume one fixed row only.
"""
import hashlib
import re
from datetime import datetime, timedelta, timezone

from factory_state.model import StateError
from .pilot002_bootstrap import TASK, CONTRACT, PINNED

TABLE = 'tims-factory-pilot-002-attempts'
ROLES = ('builder', 'inspector', 'qa')
CAP_MICRO_USD = 250000


def key(role):
    if not isinstance(role, str) or role not in ROLES:
        raise StateError('Unknown Pilot 002 provider role')
    return {'PK': {'S': f'PILOT#002#TASK#{TASK}#ROLE#{role}'}}


def _digest(value):
    return isinstance(value, str) and re.fullmatch(r'sha256:[0-9a-f]{64}', value)


class Pilot002AttemptStore:
    def __init__(self, client):
        self.client = client

    def begin(self, *, role, request_bytes, source_commit, approval_digest,
              pricing_digest, now, approval_expires_at, pricing_expires_at):
        """One atomic full-cap hold and attempt claim. Never retry uncertainty."""
        rowkey = key(role)
        times = (now, approval_expires_at, pricing_expires_at)
        if (not isinstance(request_bytes, bytes) or not 0 < len(request_bytes) <= 65536 or
                not isinstance(source_commit, str) or not re.fullmatch('[0-9a-f]{40}', source_commit) or
                not _digest(approval_digest) or not _digest(pricing_digest) or
                any(not isinstance(t, datetime) or t.tzinfo is None or t.utcoffset() is None for t in times)):
            raise StateError('Pilot 002 reservation binding invalid')
        if not (now < min(approval_expires_at, pricing_expires_at) and
                approval_expires_at <= now + timedelta(hours=1)):
            raise StateError('Pilot 002 authorization or pricing window invalid')
        digest = 'sha256:' + hashlib.sha256(request_bytes).hexdigest()
        item = {**rowkey, 'status': {'S': 'STARTED'},
            'task_id': {'S': TASK}, 'role': {'S': role},
            'contract_digest': {'S': 'sha256:' + PINNED[CONTRACT]},
            'source_commit': {'S': source_commit}, 'request_digest': {'S': digest},
            'approval_digest': {'S': approval_digest}, 'pricing_digest': {'S': pricing_digest},
            'reservation_status': {'S': 'HELD'},
            'reserved_micro_usd': {'N': str(CAP_MICRO_USD)},
            'claimed_at': {'S': now.astimezone(timezone.utc).isoformat()},
            'approval_expires_at': {'S': approval_expires_at.astimezone(timezone.utc).isoformat()},
            'pricing_expires_at': {'S': pricing_expires_at.astimezone(timezone.utc).isoformat()}}
        try:
            self.client.put_item(TableName=TABLE, Item=item,
                ConditionExpression='attribute_not_exists(PK)')
        except Exception:
            raise StateError('Pilot 002 attempt exists or is uncertain; reconcile without retry') from None
        return digest

    def complete(self, *, role, request_digest, output_bytes, actual_micro_usd):
        rowkey = key(role)
        if (not _digest(request_digest) or not isinstance(output_bytes, bytes) or
                not 0 < len(output_bytes) <= 65536 or type(actual_micro_usd) is not int or
                not 0 <= actual_micro_usd <= CAP_MICRO_USD):
            raise StateError('Pilot 002 completion invalid or over cap; retain hold')
        try:
            self.client.update_item(TableName=TABLE, Key=rowkey,
                ConditionExpression='#s = :started AND request_digest = :request AND reservation_status = :held AND reserved_micro_usd = :cap',
                UpdateExpression='SET #s = :complete, output_digest = :output, actual_micro_usd = :actual',
                ExpressionAttributeNames={'#s': 'status'}, ExpressionAttributeValues={
                    ':started': {'S': 'STARTED'}, ':complete': {'S': 'COMPLETE'},
                    ':request': {'S': request_digest}, ':held': {'S': 'HELD'},
                    ':cap': {'N': str(CAP_MICRO_USD)},
                    ':output': {'S': 'sha256:' + hashlib.sha256(output_bytes).hexdigest()},
                    ':actual': {'N': str(actual_micro_usd)}})
        except Exception:
            raise StateError('Pilot 002 completion uncertain; retain hold and do not repeat provider call') from None
