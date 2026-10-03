"""Offline exact-request owner verification; no signing or cloud/provider IO.

Trusted keys, cost bounds and readiness observations MUST be supplied by the
reviewed deployment, never by invocation fields. This verifies bindings and
signatures, not provider prices, credential access or repository commit trees.
No current live handler consumes these allowances.
"""
import base64
import copy
import hashlib
import re
from datetime import datetime, timezone

from factory_state.model import OWNER_IDENTITY, StateError
from factory_state.scope import SignedScopeStore
from .pilot002_attempts import CAP_MICRO_USD
from .pilot002_packets import builder_packet, review_packet, digest


def _hash(value):
    return isinstance(value, str) and re.fullmatch(r'sha256:[0-9a-f]{64}', value)


def _exact(value, expected, extra):
    return (isinstance(value, dict) and set(value) == set(expected) | set(extra) and
        all(type(value.get(k)) is type(v) and value[k] == v for k,v in expected.items()))


def _window(value, now, maximum_seconds):
    return (type(value.get('issued_at')) is int and type(value.get('expires_at')) is int and
        value['issued_at'] <= now.timestamp() < value['expires_at'] <= value['issued_at']+maximum_seconds)


def verify(envelope, *, root, role, request_bytes, source_commit, pricing, readiness,
           trusted_keys, now, builder_response=None, candidate_commit=None):
    """Return claim arguments only after all bindings and the owner signature pass.

request_bytes must be the complete provider-specific serialized body from the
reviewed adapter. Its wrapper/schema overhead must be included in the external
cost qualification. A packet byte count alone is never treated as a token bound.
"""
    envelope, pricing, readiness = copy.deepcopy((envelope, pricing, readiness))
    trusted_keys = dict(trusted_keys)
    if (not isinstance(now, datetime) or now.tzinfo is None or now.utcoffset() is None or
            not isinstance(source_commit, str) or not re.fullmatch('[0-9a-f]{40}', source_commit) or
            not isinstance(request_bytes, bytes) or not 0 < len(request_bytes) <= 65536):
        raise StateError('Pilot 002 allowance context invalid')
    if role == 'builder':
        if builder_response is not None or candidate_commit is not None:
            raise StateError('Builder allowance cannot substitute review material')
        packet = builder_packet(root)
    else:
        packet = review_packet(root, role=role, builder_response=builder_response, candidate_commit=candidate_commit)
    request_digest = 'sha256:' + hashlib.sha256(request_bytes).hexdigest()
    bindings = {'role':role, 'model_id':packet['model_id'], 'task_id':packet['task_id'],
        'source_commit':source_commit, 'contract_digest':packet['contract_digest'],
        'packet_digest':packet['packet_digest'], 'request_digest':request_digest}
    free = isinstance(pricing,dict) and pricing.get('kind')=='pilot002_google_free_tier_cost_bound'
    price_expected = {'kind':'pilot002_google_free_tier_cost_bound' if free else 'pilot002_qualified_request_cost_bound', **bindings,
        'currency':'USD', 'complete_request_bound_qualified':not free}
    price_extra = {'maximum_cost_micro_usd','issued_at','expires_at','evidence_digest'}
    if (not _exact(pricing, price_expected, price_extra) or
            type(pricing.get('maximum_cost_micro_usd')) is not int or
            not (role=='qa' and pricing['maximum_cost_micro_usd']==0 if free else
                0 < pricing['maximum_cost_micro_usd'] <= CAP_MICRO_USD) or
            not _hash(pricing.get('evidence_digest')) or not _window(pricing, now, 300 if free else 86400)):
        raise StateError('Pilot 002 cost bound is unqualified, changed, expired or over cap')
    ready_expected = {'kind':'pilot002_provider_readiness', **bindings,
        'credential_route_verified':True, 'model_access_verified':True,
        'repository_binding_verified':True}
    if (not _exact(readiness, ready_expected, {'issued_at','expires_at','evidence_digest'}) or
            not _hash(readiness.get('evidence_digest')) or not _window(readiness, now, 3600)):
        raise StateError('Pilot 002 provider or repository readiness is missing, changed or expired')
    expected = {'kind':'pilot002_exact_request_allowance', 'owner_identity':OWNER_IDENTITY,
        **bindings, 'pricing_digest':digest(pricing), 'readiness_digest':digest(readiness),
        'reserved_micro_usd':CAP_MICRO_USD, 'approved_cap_micro_usd':CAP_MICRO_USD,
        'maximum_provider_calls':1, 'retries':0, 'task_state_writes':0,
        'gate_authority':False, 'production_release_authorized':False}
    if not isinstance(envelope, dict) or set(envelope) != {'payload','signature'}:
        raise StateError('Pilot 002 requires a signed owner allowance')
    payload = envelope['payload']
    if (not _exact(payload, expected, {'issued_at','expires_at'}) or
            not _window(payload, now, 3600) or
            payload['expires_at'] > min(pricing['expires_at'], readiness['expires_at'])):
        raise StateError('Pilot 002 signed allowance scope, cap or window differs')
    try:
        encoded = envelope['signature']
        if not isinstance(encoded, str) or len(encoded) != 88: raise ValueError()
        signature = base64.b64decode(encoded, validate=True)
        approval_digest = SignedScopeStore('unused', None, trusted_keys)._verify(
            payload, signature, OWNER_IDENTITY, now)
        expiry = datetime.fromtimestamp(payload['expires_at'], timezone.utc)
        price_expiry = datetime.fromtimestamp(pricing['expires_at'], timezone.utc)
    except Exception:
        raise StateError('Pilot 002 owner signature verification failed') from None
    return {'role':role, 'request_bytes':request_bytes, 'source_commit':source_commit,
        'approval_digest':approval_digest, 'pricing_digest':digest(pricing), 'now':now,
        'approval_expires_at':expiry, 'pricing_expires_at':price_expiry}
