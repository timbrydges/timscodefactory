"""Disabled one-attempt role execution with authenticated predecessor receipts.

All dependencies and context are deployment-owned. There is no Lambda entry
point here and no permission to derive credentials from job/model content.
"""
import base64
import copy
import re
from datetime import datetime, timezone

from factory_state.model import StateError
from factory_state.scope import SignedScopeStore, canonical
from .handoff003_attempts import Handoff003AttemptStore
from .handoff003_authorization import verify
from .handoff003_packets import digest
from .handoff003_protocols import packet, request_bytes, parse_response
from .handoff003_receipts import IDENTITIES, sha, verify_predecessors
from .handoff003_transport import Handoff003Transport
from .pilot002_adapter import _cost
from .pilot002_workflow import _fresh
from .pilot002_protocols import MAX_INPUT_TOKENS, MAX_OUTPUT_TOKENS
from .pilot002_transport import ProviderHTTPStatusError, ProviderTimeoutError


def prepare_pricing(root, *, source_commit, qualification, predecessor_receipt_digest=None, **context):
    """Bind reviewed rates to the entire serialized request; never count tokens."""
    value = packet(root, **context)
    raw = request_bytes(root, **context)
    bindings = {key: value[key] for key in ('role', 'model_id', 'task_id', 'contract_digest', 'packet_digest')}
    bindings.update(source_commit=source_commit, request_digest=sha(raw),
                    predecessor_receipt_digest=predecessor_receipt_digest)
    expected = {'kind': 'handoff003_rate_qualification', **bindings,
        'complete_request_bound_qualified': True, 'output_token_bound': MAX_OUTPUT_TOKENS}
    extra = {'input_token_bound', 'input_micro_usd_per_million', 'output_micro_usd_per_million',
        'issued_at', 'expires_at', 'evidence_digest'}
    q = qualification
    if (not isinstance(q, dict) or set(q) != set(expected) | extra or
            any(type(q.get(k)) is not type(v) or q[k] != v for k, v in expected.items()) or
            type(q['input_token_bound']) is not int or not 0 < q['input_token_bound'] <= MAX_INPUT_TOKENS or
            any(type(q[k]) is not int or not 0 <= q[k] <= 1000000000 for k in
                ('input_micro_usd_per_million', 'output_micro_usd_per_million')) or
            type(q['issued_at']) is not int or type(q['expires_at']) is not int or
            not 0 < q['expires_at'] - q['issued_at'] <= 86400 or
            not isinstance(q['evidence_digest'], str) or not re.fullmatch('sha256:[0-9a-f]{64}', q['evidence_digest'])):
        raise StateError('Handoff complete-request rate qualification differs')
    maximum = _cost(q['input_token_bound'], MAX_OUTPUT_TOKENS, q)
    if not 0 < maximum <= 250000:
        raise StateError('Handoff qualified maximum exceeds approved cap')
    return {'kind': 'handoff003_qualified_request_cost_bound', **bindings, 'currency': 'USD',
        'complete_request_bound_qualified': True, 'maximum_cost_micro_usd': maximum,
        'issued_at': q['issued_at'], 'expires_at': q['expires_at'], 'evidence_digest': digest(q)}


class HandoffStopped(StateError):
    def __init__(self, stage, response=None, failure=None):
        self.stage = stage
        self.failure = failure if stage == 'provider' else None
        self.response = response if (stage in ('response', 'signing', 'completion') and
            type(response) is bytes and 0 < len(response) <= 262144) else None
        super().__init__('Handoff stopped at ' + stage + '; retain hold and reconcile without retry')


def run_once(envelope, *, root, role, source_commit, qualification, readiness,
             trusted_keys, store, load_credential, sign_receipt, clock, enabled=False,
             predecessors=None, predecessor_request_digests=None, candidate_commit=None):
    """Authenticate, claim once, send once, sign observed output and retain hold.

    Reviews may be signed REJECTED for audit; verify_chain still prevents their
    use as accepted evidence. This never advances task state or releases code.
    """
    if enabled is not True:
        raise StateError('Handoff workflow disabled')
    if type(store) is not Handoff003AttemptStore or not callable(sign_receipt):
        raise StateError('Handoff requires its isolated attempt store and role signer')
    stage = 'preparation'
    credential = None
    retained_response = None
    try:
        envelope, qualification, readiness, predecessors, predecessor_request_digests = copy.deepcopy(
            (envelope, qualification, readiness, predecessors, predecessor_request_digests))
        trusted_keys = dict(trusted_keys)
        observed = clock()
        builder_response = predecessor_digest = None
        predecessor_expiry = None
        if role == 'builder':
            if predecessors is not None or predecessor_request_digests is not None or candidate_commit is not None:
                raise StateError('Builder cannot accept predecessors')
        else:
            stage = 'predecessor'
            prior = verify_predecessors(predecessors, next_role=role, root=root, trusted_keys=trusted_keys,
                source_commit=source_commit, candidate_commit=candidate_commit,
                request_digests=predecessor_request_digests, now=observed)
            builder_response = prior['builder_response']
            predecessor_digest = prior['predecessor_receipt_digest']
            predecessor_expiry = datetime.fromtimestamp(
                min(item['payload']['expires_at'] for item in predecessors.values()), timezone.utc)
        context = dict(role=role, builder_response=builder_response, candidate_commit=candidate_commit)
        value = packet(root, **context)
        request = request_bytes(root, **context)
        pricing = prepare_pricing(root, source_commit=source_commit, qualification=qualification,
            predecessor_receipt_digest=predecessor_digest, **context)
        stage = 'authorization'
        args = verify(envelope, root=root, source_commit=source_commit, request_bytes=request,
            pricing=pricing, readiness=readiness, trusted_keys=trusted_keys, now=observed,
            predecessor_receipt_digest=predecessor_digest, **context)
        stage = 'reservation'
        expected_digest = sha(request)
        if store.begin(**args) != expected_digest:
            raise StateError('Claim request binding differs')
        expiry = min(args['approval_expires_at'], args['pricing_expires_at'])
        if predecessor_expiry is not None:
            expiry = min(expiry, predecessor_expiry)
        stage = 'credential'
        previous = _fresh(clock(), observed, expiry)
        credential = load_credential()
        stage = 'provider'
        previous = _fresh(clock(), previous, expiry)
        raw = Handoff003Transport(root, **context, enabled=True).send_once(
            request_bytes=request, credential=credential, expected_request_digest=expected_digest)
        credential = None
        stage = 'response'
        retained_response = raw
        result = parse_response(raw, root, **context)
        usage = result['usage']
        cost = _cost(usage['input_tokens'], usage['output_tokens_including_reasoning'], qualification)
        if usage['input_tokens'] > qualification['input_token_bound'] or cost > pricing['maximum_cost_micro_usd']:
            raise StateError('Observed usage exceeds qualified maximum')
        stage = 'signing'
        now = _fresh(clock(), previous, expiry)
        payload = {'kind': 'handoff003_role_result', 'task_id': value['task_id'], 'role': role,
            'producer_identity': IDENTITIES[role], 'model_id': value['model_id'], 'source_commit': source_commit,
            'contract_digest': value['contract_digest'], 'request_digest': expected_digest,
            'output_digest': sha(result['output_bytes']), 'predecessor_receipt_digest': predecessor_digest,
            'transport_invocations': 1, 'issued_at': int(now.timestamp()), 'expires_at': int(expiry.timestamp()),
            'actual_micro_usd': cost, 'provider_response_digest': sha(raw)}
        signature = sign_receipt(copy.deepcopy(payload), now=now)
        SignedScopeStore('unused', None, trusted_keys)._verify(payload, signature, IDENTITIES[role], now)
        signed = {'payload': payload, 'signature_base64': base64.b64encode(signature).decode(),
            'output_base64': base64.b64encode(result['output_bytes']).decode()}
        stage = 'completion'
        store.complete(role=role, request_digest=expected_digest, output_bytes=canonical(signed), actual_micro_usd=cost)
        return signed
    except Exception as error:
        failure = {'failure_category': 'unknown', 'http_status': None}
        if isinstance(error, ProviderTimeoutError):
            failure['failure_category'] = 'timeout'
        elif isinstance(error, ProviderHTTPStatusError) and type(error.http_status) is int and 300 <= error.http_status <= 599:
            failure = {'failure_category': 'http_status', 'http_status': error.http_status}
        raise HandoffStopped(stage, retained_response, failure) from None
    finally:
        credential = None
