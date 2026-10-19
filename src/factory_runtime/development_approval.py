"""Trusted-host approval boundary, not a public authorization endpoint.

The owner-authorized bit and expected pins must come from the trusted operator,
never a queue item, model output, scheduled reminder or uploaded document.
"""
from datetime import datetime, timedelta
from decimal import Decimal
import os
from pathlib import Path

from factory_state.model import StateError
from factory_state.scope import canonical
from .development_host import DevelopmentHost
from .worker import digest


def compose_approved_host(directory, *, approval, expected_pins, receipt_path,
                          now, owner_authorized=False, **options):
    if owner_authorized is not True:
        raise StateError('explicit human authorization required')
    keys = {'source_commit', 'contract_digest', 'repository', 'target_commit',
            'image_ref', 'model_id', 'attempt_id', 'credential_source',
            'builder_cap', 'reviewer_cap', 'total_cap', 'max_request_bytes',
            'max_output_tokens'}
    if (type(approval) is not dict or set(approval) != {'pins', 'expires_at'}
            or type(expected_pins) is not dict or set(expected_pins) != keys
            or canonical(approval['pins']) != canonical(expected_pins)):
        raise StateError('approval differs from trusted exact attempt pins')
    try:
        expiry = datetime.fromisoformat(approval['expires_at'])
        if now.tzinfo is None or expiry.tzinfo is None or not now < expiry <= now + timedelta(hours=24):
            raise ValueError()
        pins = expected_pins
        caps = [Decimal(pins[k]) for k in ('builder_cap', 'reviewer_cap', 'total_cap')]
        if any(not c.is_finite() or c <= 0 for c in caps) or caps[0]+caps[1] > caps[2]:
            raise ValueError()
        if any(type(pins[k]) is not int or pins[k] <= 0 for k in ('max_request_bytes', 'max_output_tokens')):
            raise ValueError()
    except (ValueError, TypeError, ArithmeticError):
        raise StateError('invalid approval lifetime or limits') from None
    task, snapshot = options['task'], options['snapshot']
    if (task.source_commit != pins['source_commit'] or task.entry_id != pins['attempt_id']
            or digest(options['contract_bytes']) != pins['contract_digest']
            or snapshot.repository != pins['repository'] or snapshot.commit != pins['target_commit']
            or options['target'].model_id != pins['model_id']
            or 'enabled' in options):
        raise StateError('runtime differs from approved attempt')
    for adapter in (options['builder'], options['reviewer']):
        if (adapter.policy.max_request_bytes > pins['max_request_bytes']
                or adapter.policy.max_output_tokens > pins['max_output_tokens']):
            raise StateError('adapter exceeds approved request bounds')
    for key, cap in zip(('builder_cap', 'reviewer_cap', 'total_cap'), caps):
        if options[key] != cap:
            raise StateError('runtime budget differs from approval')
    # Trusted host must bind injected sandbox and credential factories to the
    # approved image/source. This function does not dynamically import adapters.
    receipt = Path(receipt_path)
    if receipt.parent.is_symlink() or not receipt.parent.is_dir():
        raise StateError('regular approval receipt parent required')
    with receipt.open('xb') as handle:
        handle.write(canonical(approval))
        handle.flush()
        os.fsync(handle.fileno())
    # Construction failure consumes approval too; no automatic reconstruction.
    return DevelopmentHost(directory, enabled=True, **options)
