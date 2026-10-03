"""Read-only observation of the fixed Google attempt, never permission to retry."""
import hashlib
import re
from datetime import datetime, timezone

from factory_state.model import StateError
from factory_state.scope import canonical
from .google_qa import request_body
from .google_qa_records import parse_record
from .google_qa_boundary import ACTIVATION, KEY, TABLE
from .review_preparation import prepare

BASE = {'PK', 'SK', 'status', 'request_digest', 'approval_digest', 'source_commit'}
HOLD = {'pricing_digest', 'reservation_status', 'reserved_micro_usd',
        'approved_cap_micro_usd', 'claimed_at', 'approval_expires_at', 'pricing_expires_at'}
FREE = {'billing_mode','billing_evidence_digest','billing_verified_at'}


def _field(item, name, kind='S'):
    value = item.get(name)
    if not isinstance(value, dict) or set(value) != {kind} or not isinstance(value[kind], str):
        raise StateError('Google ledger field malformed')
    return value[kind]


def _digest(value):
    if not re.fullmatch(r'sha256:[0-9a-f]{64}', value):
        raise StateError('Google ledger digest malformed')
    return value


def _time(value):
    try:
        parsed = datetime.fromisoformat(value)
        if parsed.tzinfo is None or parsed.utcoffset() is None:
            raise ValueError()
        return parsed
    except ValueError:
        raise StateError('Google ledger time malformed') from None


def _response(raw, packet, root):
    value = parse_record(raw.encode(), packet, root=root)
    return {'response_digest': 'sha256:' + hashlib.sha256(canonical(value)).hexdigest(),
            'assessment_verdict': value['assessment']['verdict']}


def inspect_item(item, *, root, source_commit, observed_at):
    """Validate a snapshot; even absence does not authorize generation or replay."""
    if (not isinstance(source_commit, str) or not re.fullmatch('[0-9a-f]{40}', source_commit) or
            not isinstance(observed_at, datetime) or observed_at.tzinfo is None or observed_at.utcoffset() is None):
        raise StateError('Google reconciliation scope invalid')
    packet = prepare(root, role='qa')
    digest = 'sha256:' + hashlib.sha256(request_body(packet, root=root)).hexdigest()
    result = {'activation_id': ACTIVATION, 'expected_source_commit': source_commit,
        'request_digest': digest, 'observed_at': observed_at.astimezone(timezone.utc).isoformat(),
        'retry_authorized': False, 'generation_authorized': False,
        'reservation_released': False, 'gate_authority': False,
        'production_release_authorized': False}
    if item is None:
        return {**result, 'status': 'ABSENT_AT_OBSERVATION_NOT_AUTHORIZED'}
    if not isinstance(item, dict) or any(item.get(k) != v for k, v in KEY.items()):
        raise StateError('Google ledger key differs')
    status = _field(item, 'status')
    held = bool(set(item) & HOLD)
    free = bool(set(item) & FREE)
    expected_fields = BASE | (HOLD if held else set()) | (FREE if free else set()) | ({'response'} if status == 'COMPLETE' else set())
    if (status not in ('STARTED', 'COMPLETE') or set(item) != expected_fields or
            _field(item, 'source_commit') != source_commit or _field(item, 'request_digest') != digest):
        raise StateError('Google ledger scope or shape differs; manual reconciliation required')
    if free and not held:
        raise StateError('Google free-tier record requires an atomic claim')
    _digest(_field(item, 'approval_digest'))
    if held:
        _digest(_field(item, 'pricing_digest'))
        amounts = [_field(item, k, 'N') for k in ('reserved_micro_usd', 'approved_cap_micro_usd')]
        if (any(not re.fullmatch('0|[1-9][0-9]{0,6}', n) for n in amounts) or
                not (amounts == ['0','0'] if free else 0 < int(amounts[0]) <= int(amounts[1]) <= 1000000) or
                _field(item, 'reservation_status') != 'HELD'):
            raise StateError('Google ledger reservation differs')
        claimed, approval, pricing = [_time(_field(item, k)) for k in
            ('claimed_at', 'approval_expires_at', 'pricing_expires_at')]
        if claimed >= min(approval, pricing) or claimed > observed_at:
            raise StateError('Google ledger claim time differs')
        if free:
            billing_time = _time(_field(item,'billing_verified_at'))
            _digest(_field(item,'billing_evidence_digest'))
            if (_field(item,'billing_mode') != 'UNLINKED_FREE_TIER' or
                    not billing_time.timestamp() <= claimed.timestamp() < approval.timestamp() <= billing_time.timestamp()+300):
                raise StateError('Google free-tier ledger billing evidence differs')
            result['billing_mode'] = 'UNLINKED_FREE_TIER'
        result.update(reserved_micro_usd=int(amounts[0]), approved_cap_micro_usd=int(amounts[1]),
                      approval_or_pricing_expired=observed_at >= min(approval, pricing))
    if status == 'COMPLETE':
        result.update(_response(_field(item, 'response'), packet, root))
    result['status'] = (('COMPLETE_UNSIGNED_HOLD_RETAINED' if status == 'COMPLETE' else
                         'STARTED_HELD_OUTCOME_UNKNOWN') if held else 'LEGACY_UNRESERVED_REQUIRES_RECONCILIATION')
    return result


def observe(client, *, root, source_commit, observed_at):
    # Validate caller scope and pinned material before reading any cloud data.
    inspect_item(None, root=root, source_commit=source_commit, observed_at=observed_at)
    try:
        response = client.get_item(TableName=TABLE, Key=KEY, ConsistentRead=True)
    except Exception:
        raise StateError('Google ledger read uncertain; no retry or generation authorized') from None
    if not isinstance(response, dict) or ('Item' in response and not response['Item']):
        raise StateError('Google ledger read malformed')
    return inspect_item(response.get('Item'), root=root, source_commit=source_commit, observed_at=observed_at)
