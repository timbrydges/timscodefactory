"""Unwired one-attempt orchestration; no default clients or provider adapters.

Dependencies are deployment-owned, never invocation-supplied. Adapters must
build deterministic complete requests, send once without retries/redirects,
and validate provider model identity, completion, usage and actual cost.
This module neither creates credentials nor implements those provider adapters.
"""
import copy
import hashlib
from datetime import datetime

from factory_state.model import StateError
from factory_state.scope import canonical
from .pilot002_attempts import Pilot002AttemptStore, CAP_MICRO_USD
from .pilot002_authorization import verify
from .pilot002_packets import builder_packet, review_packet, parse_builder, parse_review


def _fresh(now, previous, expiry):
    if (not isinstance(now, datetime) or now.tzinfo is None or now.utcoffset() is None or
            now < previous or now >= expiry):
        raise StateError('Pilot 002 approval expired or clock moved backwards')
    return now


def run_once(envelope, *, root, role, source_commit, pricing, readiness, trusted_keys,
             store, load_credential, adapter, clock, enabled=False,
             builder_response=None, candidate_commit=None):
    """Verify, atomically claim, load credential, send once, validate, complete.

No failure refunds a hold, deletes an attempt or retries any provider call.
Successful results are still untrusted and cannot advance a Factory state.
"""
    if enabled is not True:
        raise StateError('Pilot 002 workflow disabled')
    if not isinstance(store, Pilot002AttemptStore):
        raise StateError('Pilot 002 requires the atomic fixed-role attempt store')
    stage = 'preparation'; credential = None
    try:
        envelope, pricing, readiness = copy.deepcopy((envelope, pricing, readiness))
        trusted_keys = dict(trusted_keys)
        packet = (builder_packet(root) if role == 'builder' else
            review_packet(root, role=role, builder_response=builder_response, candidate_commit=candidate_commit))
        request_bytes = adapter.build_request(copy.deepcopy(packet))
        stage = 'authorization'
        args = verify(envelope, root=root, role=role, request_bytes=request_bytes,
            source_commit=source_commit, pricing=pricing, readiness=readiness,
            trusted_keys=trusted_keys, now=clock(), builder_response=builder_response,
            candidate_commit=candidate_commit)
        expected_digest = 'sha256:' + hashlib.sha256(request_bytes).hexdigest()
        stage = 'reservation'
        if store.begin(**args) != expected_digest:
            raise StateError('Pilot 002 claim binding differs')
        expiry = min(args['approval_expires_at'], args['pricing_expires_at'])
        stage = 'expiry_before_credential'
        previous = _fresh(clock(), args['now'], expiry)
        stage = 'credential'
        credential = load_credential()
        stage = 'expiry_before_provider'
        _fresh(clock(), previous, expiry)
        stage = 'provider'
        raw = adapter.send_once(request_bytes=request_bytes, credential=credential,
            expected_request_digest=expected_digest)
        credential = None
        stage = 'response'
        if not isinstance(raw, bytes) or not 0 < len(raw) <= 262144:
            raise StateError('Pilot 002 raw provider response exceeds bound')
        result = copy.deepcopy(adapter.parse_response(raw, copy.deepcopy(packet)))
        if (not isinstance(result, dict) or set(result) != {'model_id','output_bytes','actual_micro_usd'} or
                result['model_id'] != packet['model_id'] or
                type(result['actual_micro_usd']) is not int or
                not 0 <= result['actual_micro_usd'] <= pricing['maximum_cost_micro_usd'] <= CAP_MICRO_USD):
            raise StateError('Pilot 002 provider result identity or cost differs')
        output = (parse_builder(result['output_bytes'], root=root) if role == 'builder' else
            parse_review(result['output_bytes'], root=root, role=role,
                builder_response=builder_response, candidate_commit=candidate_commit))
        record = {'status':'PILOT002_COMPLETED_UNSIGNED', 'role':role,
            'model_id':packet['model_id'], 'source_commit':source_commit,
            'request_digest':expected_digest, 'approval_digest':args['approval_digest'],
            'provider_response_digest':'sha256:' + hashlib.sha256(raw).hexdigest(),
            'actual_micro_usd':result['actual_micro_usd'], 'output':output,
            'transport_invocations':1, 'reservation_status':'HELD',
            'gate_authority':False, 'production_release_authorized':False}
        stage = 'completion'
        store.complete(role=role, request_digest=expected_digest, output_bytes=canonical(record),
            actual_micro_usd=result['actual_micro_usd'])
        return record
    except Exception:
        # Provider exceptions can contain credentials or raw request content.
        # Never expose them or use an uncertain result to permit another call.
        raise StateError('Pilot 002 stopped at '+stage+'; reconcile without retry') from None
    finally:
        credential = None
