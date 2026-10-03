"""Unwired one-attempt workflow. No default cloud clients or live entry point.

The runtime must supply enrolled owner keys, qualified pinned pricing, a clock,
the isolated reservation store and broker-only credential/transport dependencies.
No signature producer, owner approval, pricing evidence or runtime flag is added.
"""
import copy
import hashlib
from datetime import datetime

from factory_state.model import StateError
from .google_qa import parse_response
from .google_qa_authorization import verify
from .google_qa_reservation import GoogleQaReservedAttemptStore
from .review_preparation import prepare


def run_once(envelope, *, root, source_commit, pricing, trusted_keys, store, load_key, transport, clock):
    if not isinstance(store, GoogleQaReservedAttemptStore):
        raise StateError('Google workflow requires atomic reservation and attempt storage')
    # Caller-owned mutable dictionaries cannot change between verification and
    # the hold. The transport independently checks the exact reserved request.
    packet = prepare(root, role='qa')
    stage = 'authorization'
    key = None
    try:
        args = verify(copy.deepcopy(envelope), packet=packet, root=root, source_commit=source_commit,
            pricing=copy.deepcopy(pricing), trusted_keys=dict(trusted_keys), now=clock())
        stage = 'reservation'
        expected_digest = 'sha256:'+hashlib.sha256(args['request_bytes']).hexdigest()
        actual_digest = store.begin(**args)
        if actual_digest != expected_digest:
            raise StateError('reservation binding differs')
        stage = 'credential'
        key = load_key()
        stage = 'expiry'
        now = clock()
        if (not isinstance(now, datetime) or now.tzinfo is None or now.utcoffset() is None or
                now < args['now'] or now >= min(args['approval_expires_at'],args['pricing_expires_at'])):
            raise StateError('approval expired or clock moved backwards before provider request')
        stage = 'provider'
        raw = transport.send_once(packet, root=root, api_key=key, expected_request_digest=expected_digest)
        key = None
        stage = 'response'
        response = parse_response(raw, packet, root=root)
        stage = 'completion'
        store.complete(request_digest=expected_digest, response=response)
        return {'status':'GOOGLE_QA_COMPLETE_UNSIGNED','request_digest':expected_digest,
                'response':response,'reservation_status':'HELD','gate_authority':False,
                'production_release_authorized':False}
    except Exception:
        # Never propagate raw provider/credential exceptions. Never retry, read
        # back to infer permission, release money, delete a claim or change keys.
        raise StateError('Google QA stopped at '+stage+'; reconcile without retry') from None
    finally:
        key = None
