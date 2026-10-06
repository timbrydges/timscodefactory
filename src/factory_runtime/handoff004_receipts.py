"""Authenticate the ordered fresh handoff; no calls, writes or state authority."""
import base64
import copy
import hashlib
import re
from datetime import datetime

from factory_state.model import StateError
from factory_state.scope import SignedScopeStore
from . import handoff004_packets as packets

IDENTITIES = {'builder':'engineering_agent_service',
              'inspector':'independent_inspector_service', 'qa':'qa_engineer_service'}


def sha(raw):
    return 'sha256:' + hashlib.sha256(raw).hexdigest()


def _verify_sequence(envelopes, *, roles, root, trusted_keys, source_commit,
                     candidate_commit, request_digests, now):
    if (roles not in (('builder',), ('builder', 'inspector'), tuple(IDENTITIES)) or
            not isinstance(envelopes, dict) or set(envelopes) != set(roles) or
            not isinstance(request_digests, dict) or set(request_digests) != set(roles) or
            any(not isinstance(v, str) or not re.fullmatch('sha256:[0-9a-f]{64}', v)
                for v in request_digests.values()) or
            any(not isinstance(v, str) or not re.fullmatch('[0-9a-f]{40}', v)
                for v in (source_commit, candidate_commit))):
        raise StateError('Handoff expected bindings or executed-test verifier missing')
    # No keys may arrive from envelopes or provider content; duplicate material
    # across identities is rejected by the existing signature verifier.
    if not isinstance(now, datetime) or now.tzinfo is None or now.utcoffset() is None:
        raise StateError('Handoff verification requires an aware current time')
    try:
        keys = {identity: trusted_keys[identity] for identity in IDENTITIES.values()}
        scope = SignedScopeStore('unused', None, keys)
    except (KeyError, TypeError, ValueError, StateError):
        raise StateError('Handoff independent trusted keys missing or invalid') from None
    contract, _, _ = packets.facts(root)
    models = {p['role']: p['model_id'] for p in contract['providers']}
    previous = None
    builder_raw = None
    candidate_digest = None
    reported_total = 0
    receipts = {}
    for role in roles:
        identity = IDENTITIES[role]
        envelope = copy.deepcopy(envelopes[role])
        try:
            if not isinstance(envelope, dict) or set(envelope) != {'payload', 'signature_base64', 'output_base64'}:
                raise ValueError('envelope')
            if any(not isinstance(envelope[k], str) or len(envelope[k]) > limit
                   for k, limit in (('signature_base64', 88), ('output_base64', 44000))):
                raise ValueError('size')
            output = base64.b64decode(envelope['output_base64'], validate=True)
            signature = base64.b64decode(envelope['signature_base64'], validate=True)
            payload = envelope['payload']
            expected = {'kind':'handoff004_role_result', 'task_id':packets.TASK,
                'role':role, 'producer_identity':identity, 'model_id':models[role],
                'source_commit':source_commit, 'contract_digest':'sha256:'+packets.PINNED[packets.CONTRACT],
                'request_digest':request_digests[role], 'output_digest':sha(output),
                'predecessor_receipt_digest':previous, 'transport_invocations':1}
            extra = {'issued_at', 'expires_at', 'actual_micro_usd', 'provider_response_digest'}
            if (not isinstance(payload, dict) or set(payload) != set(expected) | extra or
                    any(type(payload.get(k)) is not type(v) or payload[k] != v for k, v in expected.items()) or
                    type(payload['actual_micro_usd']) is not int or not 0 <= payload['actual_micro_usd'] <= 250000 or
                    not isinstance(payload['provider_response_digest'], str) or
                    not re.fullmatch('sha256:[0-9a-f]{64}', payload['provider_response_digest']) or
                    type(payload['issued_at']) is not int or type(payload['expires_at']) is not int or
                    not 0 < payload['expires_at'] - payload['issued_at'] <= 3600):
                raise ValueError('bindings')
            receipt = scope._verify(payload, signature, identity, now)
        except (KeyError, TypeError, ValueError, StateError):
            raise StateError('Handoff receipt signature or exact bindings rejected') from None
        if role == 'builder':
            candidate = packets.parse_builder(output, root=root)
            builder_raw = output
            candidate_digest = candidate['candidate_digest']
        else:
            review = packets.parse_review(output, root=root, role=role,
                builder_response=builder_raw, candidate_commit=candidate_commit)
            if review['verdict'] != 'ACCEPTED':
                raise StateError('Handoff review rejected; no retry or automatic progression')
        receipts[role] = receipt
        previous = receipt
        reported_total += payload['actual_micro_usd']
    return builder_raw, candidate_digest, receipts, reported_total


def verify_predecessors(envelopes, *, next_role, **context):
    """Authenticate the complete prefix before consuming the next paid attempt."""
    if next_role not in ('inspector', 'qa'):
        raise StateError('Only reviewers have handoff predecessors')
    roles = ('builder',) if next_role == 'inspector' else ('builder', 'inspector')
    raw, candidate, receipts, _ = _verify_sequence(envelopes, roles=roles, **context)
    return {'builder_response': raw, 'candidate_digest': candidate,
        'predecessor_receipt_digest': receipts[roles[-1]], 'gate_authority': False}


def verify_chain(envelopes, *, root, trusted_keys, source_commit, candidate_commit,
                 request_digests, now, verify_executed_tests):
    """Authenticate all roles and independently executed tests; no state authority.

    Expected bindings, trusted keys and the verifier are deployment-owned inputs.
    Provider claims to have executed tests can never supply the test verifier.
    """
    if not callable(verify_executed_tests):
        raise StateError('Handoff requires an independent executed-test verifier')
    _, candidate_digest, receipts, reported_total = _verify_sequence(envelopes,
        roles=tuple(IDENTITIES), root=root, trusted_keys=trusted_keys,
        source_commit=source_commit, candidate_commit=candidate_commit,
        request_digests=request_digests, now=now)
    try:
        tested = verify_executed_tests(candidate_commit, candidate_digest)
    except Exception:
        raise StateError('Independent execution verification failed') from None
    if tested is not True:
        raise StateError('Exact candidate lacks independently verified passing tests')
    return {'status':'AUTHENTICATED_HANDOFF_VERIFIED', 'task_id':packets.TASK,
        'source_commit':source_commit, 'candidate_commit':candidate_commit,
        'candidate_digest':candidate_digest, 'receipt_digests':receipts,
        'reported_actual_micro_usd':reported_total, 'reservation_micro_usd':750000,
        'invoice_verified':False, 'gate_authority':False, 'production_release_authorized':False}
