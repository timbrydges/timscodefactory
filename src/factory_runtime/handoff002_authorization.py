"""Fresh exact-request authorization; no signing, cloud writes or model calls."""
import base64
from datetime import datetime, timezone
import re

from factory_state.model import OWNER_IDENTITY, StateError
from factory_state.scope import SignedScopeStore
from .handoff002_packets import facts, PINNED, APPROVAL, digest
from .handoff002_protocols import packet, request_bytes as prepare_request
from .pilot002_authorization import _exact, _window, _hash
from .handoff002_receipts import sha


def validate_unsigned(payload, *, root, role, request_bytes, source_commit, pricing, readiness,
           now, predecessor_receipt_digest=None,
           builder_response=None, candidate_commit=None):
    """Pricing/readiness and predecessor bindings must be deployment-owned.

    A previous signed receipt must be independently verified before its digest
    enters this function. This verifies owner permission, not predecessor origin
    or provider availability. Old pilot allowances can never match this kind.
    """
    facts(root)
    context = dict(role=role, builder_response=builder_response, candidate_commit=candidate_commit)
    if (not isinstance(now, datetime) or now.tzinfo is None or now.utcoffset() is None or
            not isinstance(source_commit, str) or not re.fullmatch('[0-9a-f]{40}', source_commit) or
            type(request_bytes) is not bytes or request_bytes != prepare_request(root, **context) or
            (predecessor_receipt_digest is not None if role == 'builder' else not _hash(predecessor_receipt_digest))):
        raise StateError('Handoff allowance context or exact request differs')
    value = packet(root, **context)
    bindings = {'role': role, 'model_id': value['model_id'], 'task_id': value['task_id'],
        'source_commit': source_commit, 'contract_digest': value['contract_digest'],
        'packet_digest': value['packet_digest'], 'request_digest': sha(request_bytes),
        'predecessor_receipt_digest': predecessor_receipt_digest}
    price_expected = {'kind': 'handoff002_qualified_request_cost_bound', **bindings,
        'currency': 'USD', 'complete_request_bound_qualified': True}
    if (not _exact(pricing, price_expected,
            {'maximum_cost_micro_usd', 'issued_at', 'expires_at', 'evidence_digest'}) or
            type(pricing['maximum_cost_micro_usd']) is not int or
            not 0 < pricing['maximum_cost_micro_usd'] <= 250000 or
            not _hash(pricing['evidence_digest']) or not _window(pricing, now, 86400)):
        raise StateError('Handoff pricing is missing, changed, expired or over cap')
    ready_expected = {'kind': 'handoff002_provider_readiness', **bindings,
        'credential_route_verified': True, 'model_metadata_verified': True,
        'repository_binding_verified': True, 'single_attempt_failure_risk_accepted': True}
    if (not _exact(readiness, ready_expected, {'issued_at', 'expires_at', 'evidence_digest'}) or
            not _hash(readiness['evidence_digest']) or not _window(readiness, now, 3600)):
        raise StateError('Handoff provider readiness is missing, changed or expired')
    expected = {'kind': 'handoff002_exact_request_allowance', 'owner_identity': OWNER_IDENTITY,
        **bindings, 'budget_approval_digest': 'sha256:' + PINNED[APPROVAL],
        'pricing_digest': digest(pricing), 'readiness_digest': digest(readiness),
        'reserved_micro_usd': 250000, 'approved_cap_micro_usd': 250000,
        'maximum_provider_calls': 1, 'retries': 0, 'task_state_writes': 0,
        'gate_authority': False, 'production_release_authorized': False}
    if (not _exact(payload, expected, {'issued_at', 'expires_at'}) or
            not _window(payload, now, 3600) or
            payload['expires_at'] > min(pricing['expires_at'], readiness['expires_at'])):
        raise StateError('Handoff signed scope, cap or window differs')
    return {'role': role, 'request_bytes': request_bytes, 'source_commit': source_commit,
        'pricing_digest': digest(pricing), 'now': now,
        'approval_expires_at': datetime.fromtimestamp(payload['expires_at'], timezone.utc),
        'pricing_expires_at': datetime.fromtimestamp(pricing['expires_at'], timezone.utc)}


def verify(envelope, *, trusted_keys, **context):
    if not isinstance(envelope, dict) or set(envelope) != {'payload', 'signature'}:
        raise StateError('Handoff requires a signed owner allowance')
    payload = envelope['payload']
    result = validate_unsigned(payload, **context)
    try:
        encoded = envelope['signature']
        if not isinstance(encoded, str) or len(encoded) != 88: raise ValueError('signature')
        signature = base64.b64decode(encoded, validate=True)
        approval_digest = SignedScopeStore('unused', None, trusted_keys)._verify(
            payload, signature, OWNER_IDENTITY, context['now'])
    except Exception:
        raise StateError('Handoff owner signature rejected') from None
    return {**result, 'approval_digest': approval_digest}
