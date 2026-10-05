"""Offline recovery-specific signature verification. No signer, clients or IO beyond scope files.

Pricing, readiness and enrolled public keys must come from reviewed deployment
material, never invocation fields. This does not independently prove observations.
"""
import base64
import copy
import re
from datetime import datetime,timezone

from factory_state.model import OWNER_IDENTITY,StateError
from factory_state.scope import SignedScopeStore
from .qa_recovery003 import RecoveryAttemptStore,CANDIDATE,CAP,PK,TABLE,SCOPE_SHA256,digest
from .pilot002_authorization import _exact,_window,_hash,validate_readiness
from .qa_recovery003_packets import review_packet
from .qa_recovery003_protocols import request_bytes as prepare_request

KIND='qa_recovery003_exact_request_allowance'
BUILDER_DIGEST='sha256:bc95e2daa9f825dd6128008b420051729431524439fdce01d515499c4d93457a'
REQUEST_DIGEST='sha256:f92747ae546698e664537981cf9d19ae8980d8fc9c56c0ac074755d3e81f11f4'


def verify(envelope, *, root, request_bytes, source_commit, pricing, readiness,
           trusted_keys, now, builder_response, candidate_commit):
    envelope,pricing,readiness=copy.deepcopy((envelope,pricing,readiness))
    trusted_keys=dict(trusted_keys)
    # Hash-pinned preparation scope, checked without enabling or using a client.
    RecoveryAttemptStore(None,root=root)
    if (not isinstance(now,datetime) or now.tzinfo is None or now.utcoffset() is None or
            candidate_commit!=CANDIDATE or type(source_commit) is not str or
            not re.fullmatch('[0-9a-f]{40}',source_commit) or type(request_bytes) is not bytes or
            not 0<len(request_bytes)<=65536 or type(builder_response) is not bytes or
            not 0<len(builder_response)<=33000 or digest(builder_response)!=BUILDER_DIGEST):
        raise StateError('Recovery allowance context differs')
    expected_request=prepare_request(root,role='qa',builder_response=builder_response,candidate_commit=CANDIDATE)
    if request_bytes!=expected_request or digest(request_bytes)!=REQUEST_DIGEST:
        raise StateError('Recovery request differs from reviewed candidate')
    packet=review_packet(root,role='qa',builder_response=builder_response,candidate_commit=CANDIDATE)
    bindings={'role':'qa','model_id':packet['model_id'],'task_id':packet['task_id'],
        'source_commit':source_commit,'contract_digest':packet['contract_digest'],
        'packet_digest':packet['packet_digest'],'request_digest':REQUEST_DIGEST}
    price_expected={'kind':'pilot002_google_free_tier_cost_bound',**bindings,
        'currency':'USD','complete_request_bound_qualified':False}
    if (not _exact(pricing,price_expected,{'maximum_cost_micro_usd','issued_at','expires_at','evidence_digest'}) or
            type(pricing.get('maximum_cost_micro_usd')) is not int or
            pricing['maximum_cost_micro_usd']!=0 or not _hash(pricing.get('evidence_digest')) or
            not _window(pricing,now,300)):
        raise StateError('Recovery cost bound invalid or stale')
    validate_readiness(readiness,bindings=bindings,now=now)
    if readiness['kind']!='pilot002_reviewer_first_generation_readiness':
        raise StateError('Explicit QA first-generation risk acceptance required')
    from factory_runtime.qa_recovery003_packets import digest as document_digest
    expected={'kind':KIND,'owner_identity':OWNER_IDENTITY,**bindings,
        'candidate_commit':CANDIDATE,'recovery_scope_digest':'sha256:'+SCOPE_SHA256,
        'attempt_table':TABLE,'attempt_key':PK,'pricing_digest':document_digest(pricing),
        'readiness_digest':document_digest(readiness),'reserved_micro_usd':CAP,'approved_cap_micro_usd':CAP,
        'maximum_provider_calls':1,'retries':0,'task_state_writes':0,
        'capture_failed_review_response':True,'maximum_captured_response_bytes':262144,
        'gate_authority':False,'production_release_authorized':False}
    if type(envelope) is not dict or set(envelope)!={'payload','signature'}:
        raise StateError('Recovery requires its own owner-signed allowance')
    payload=envelope['payload']
    if (not _exact(payload,expected,{'issued_at','expires_at'}) or not _window(payload,now,300) or
            payload['expires_at']>min(pricing['expires_at'],readiness['expires_at'])):
        raise StateError('Recovery allowance scope, retention or expiry differs')
    try:
        encoded=envelope['signature']
        if type(encoded) is not str or len(encoded)!=88:raise ValueError()
        signature=base64.b64decode(encoded,validate=True)
        approval=SignedScopeStore('unused',None,trusted_keys)._verify(payload,signature,OWNER_IDENTITY,now)
    except Exception:
        raise StateError('Recovery owner signature verification failed') from None
    return {'candidate_commit':CANDIDATE,'source_commit':source_commit,'request_bytes':request_bytes,
        'approval_digest':approval,'pricing_digest':document_digest(pricing),
        'maximum_cost_micro_usd':pricing['maximum_cost_micro_usd'],'now':now,
        'approval_expires_at':datetime.fromtimestamp(payload['expires_at'],timezone.utc),
        'pricing_expires_at':datetime.fromtimestamp(pricing['expires_at'],timezone.utc)}
