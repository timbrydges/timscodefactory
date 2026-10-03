"""Verify exact owner consent against deployment-trusted Google pricing evidence.

Trusted keys and pricing must come from reviewed deployment configuration, never
the invocation payload. No production pricing qualification or consent is added.
"""
import base64
import hashlib
import re
from datetime import datetime, timezone

from factory_state.model import OWNER_IDENTITY, StateError
from factory_state.scope import SignedScopeStore, canonical
from .google_qa import ENDPOINT, MODEL, MAX_INPUT_TOKENS, MAX_OUTPUT_TOKENS, request_body
from .google_qa_boundary import ACTIVATION


def digest(value):
    return 'sha256:' + hashlib.sha256(canonical(value)).hexdigest()


def verify(envelope, *, packet, root, source_commit, pricing, trusted_keys, now):
    if (not isinstance(now, datetime) or now.tzinfo is None or now.utcoffset() is None or
            not isinstance(source_commit, str) or not re.fullmatch('[0-9a-f]{40}', source_commit)):
        raise StateError('Google authorization context invalid')
    body = request_body(packet, root=root)
    expected_pricing = {'kind':'google_qa_pricing_envelope','model_id':MODEL,'endpoint':ENDPOINT,
        'currency':'USD','maximum_input_tokens':MAX_INPUT_TOKENS,
        'maximum_output_tokens_including_thinking':MAX_OUTPUT_TOKENS,
        'combined_output_bound_qualified':True}
    numeric = ('input_micro_usd_per_million_tokens','output_micro_usd_per_million_tokens',
               'issued_at','expires_at')
    if (not isinstance(pricing, dict) or set(pricing) != set(expected_pricing) | set(numeric) | {'evidence_digest'} or
            any(type(pricing.get(k)) is not type(v) or pricing[k] != v for k,v in expected_pricing.items()) or
            any(type(pricing.get(k)) is not int for k in numeric) or
            not 0 < pricing['input_micro_usd_per_million_tokens'] <= 1000000000 or
            not 0 < pricing['output_micro_usd_per_million_tokens'] <= 1000000000 or
            not pricing['issued_at'] <= now.timestamp() < pricing['expires_at'] or
            not isinstance(pricing.get('evidence_digest'), str) or
            not re.fullmatch('sha256:[0-9a-f]{64}', pricing['evidence_digest'])):
        raise StateError('Google pricing or combined token bound unqualified, invalid or expired')
    # Integer arithmetic, rounded UP to a micro-dollar; never use observed/free
    # tier pricing or a post-response token check as a pre-request spending cap.
    numerator = (MAX_INPUT_TOKENS * pricing['input_micro_usd_per_million_tokens'] +
                 MAX_OUTPUT_TOKENS * pricing['output_micro_usd_per_million_tokens'])
    reserved = (numerator + 999999) // 1000000
    expected = {'kind':'google_qa_allowance','owner_identity':OWNER_IDENTITY,
        'activation_id':ACTIVATION,'source_commit':source_commit,'model_id':MODEL,'endpoint':ENDPOINT,
        'candidate_commit':packet['candidate_commit'],'contract_digest':packet['contract_digest'],
        'packet_digest':packet['packet_digest'],
        'request_digest':'sha256:'+hashlib.sha256(body).hexdigest(),
        'pricing_digest':digest(pricing),'reserved_micro_usd':reserved,
        'maximum_provider_calls':1,'retries':0,'task_state_writes':0,
        'gate_authority':False,'production_release_authorized':False}
    if not isinstance(envelope, dict) or set(envelope) != {'payload','signature'}:
        raise StateError('Google requires a signed owner allowance')
    payload = envelope['payload']
    if (not isinstance(payload, dict) or set(payload) != set(expected) | {'approved_cap_micro_usd','issued_at','expires_at'} or
            any(type(payload.get(k)) is not type(v) or payload[k] != v for k,v in expected.items()) or
            type(payload.get('approved_cap_micro_usd')) is not int or
            not 0 < reserved <= payload['approved_cap_micro_usd'] <= 1000000 or
            type(payload.get('issued_at')) is not int or type(payload.get('expires_at')) is not int or
            not payload['issued_at'] <= now.timestamp() < payload['expires_at'] <= pricing['expires_at']):
        raise StateError('Google signed allowance scope, amount or lifetime differs')
    try:
        if not isinstance(envelope['signature'], str) or len(envelope['signature']) != 88:
            raise ValueError()
        signature = base64.b64decode(envelope['signature'], validate=True)
        approval_digest = SignedScopeStore('unused', None, trusted_keys)._verify(
            payload, signature, OWNER_IDENTITY, now)
        expiry = datetime.fromtimestamp(payload['expires_at'], timezone.utc)
        pricing_expiry = datetime.fromtimestamp(pricing['expires_at'], timezone.utc)
    except Exception:
        raise StateError('Google owner signature or lifetime verification failed') from None
    return {'request_bytes':body,'approval_digest':approval_digest,'source_commit':source_commit,
        'reserved_micro_usd':reserved,'approved_cap_micro_usd':payload['approved_cap_micro_usd'],
        'pricing_digest':expected['pricing_digest'],'approval_expires_at':expiry,
        'pricing_expires_at':pricing_expiry,'now':now}
