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


def approval_pins_match(approval, expected_pins, *, execution_profile=None):
    """Exact pin-set and approval equality; safe to call before any external action."""
    keys = {'source_commit', 'contract_digest', 'repository', 'target_commit',
            'image_ref', 'model_id', 'attempt_id', 'credential_source',
            'builder_cap', 'reviewer_cap', 'total_cap', 'max_request_bytes',
            'max_output_tokens'}
    if execution_profile is not None:
        keys.add('execution_profile_digest')
    if type(expected_pins) is dict and 'source_config_digest' in expected_pins:
        # Private-source attempts bind the acquisition config and expected content as a pair.
        keys |= {'source_config_digest', 'source_manifest_digest'}
    if type(expected_pins) is dict and 'repair_rounds' in expected_pins:
        # Owner-approved bounded repair; the total cap must cover every round.
        keys.add('repair_rounds')
        if type(expected_pins['repair_rounds']) is not int or expected_pins['repair_rounds'] not in (1, 2):
            raise StateError('approval permits at most two repair rounds')
    if (type(approval) is not dict or set(approval) != {'pins', 'expires_at'}
            or type(expected_pins) is not dict or set(expected_pins) != keys
            or canonical(approval['pins']) != canonical(expected_pins)):
        raise StateError('approval differs from trusted exact attempt pins')
    return True


def compose_approved_host(directory, *, approval, expected_pins, receipt_path,
                          now, owner_authorized=False, execution_profile=None, **options):
    if owner_authorized is not True:
        raise StateError('explicit human authorization required')
    approval_pins_match(approval, expected_pins, execution_profile=execution_profile)
    try:
        expiry = datetime.fromisoformat(approval['expires_at'])
        if now.tzinfo is None or expiry.tzinfo is None or not now < expiry <= now + timedelta(hours=24):
            raise ValueError()
        pins = expected_pins
        caps = [Decimal(pins[k]) for k in ('builder_cap', 'reviewer_cap', 'total_cap')]
        rounds = 1 + pins.get('repair_rounds', 0)
        if any(not c.is_finite() or c <= 0 for c in caps) or (caps[0]+caps[1])*rounds > caps[2]:
            raise ValueError()
        if any(type(pins[k]) is not int or pins[k] <= 0 for k in ('max_request_bytes', 'max_output_tokens')):
            raise ValueError()
    except (ValueError, TypeError, ArithmeticError):
        raise StateError('invalid approval lifetime or limits') from None
    task, snapshot = options['task'], options['snapshot']
    if execution_profile is not None:
        from .development_profile import TaskExecutionProfile
        if type(execution_profile) is not TaskExecutionProfile:
            raise StateError('trusted execution profile required')
        execution_profile.validate_binding(pins=pins, task=task,
                                           contract_bytes=options['contract_bytes'])
        if options.get('delivery') != execution_profile.delivery:
            raise StateError('runtime delivery differs from execution profile')
    if (task.source_commit != pins['source_commit'] or task.entry_id != pins['attempt_id']
            or digest(options['contract_bytes']) != pins['contract_digest']
            or snapshot.repository != pins['repository'] or snapshot.commit != pins['target_commit']
            or options['target'].model_id != pins['model_id']
            or 'enabled' in options):
        raise StateError('runtime differs from approved attempt')
    if 'source_manifest_digest' in pins:
        from .private_source import snapshot_manifest_digest
        if snapshot_manifest_digest(snapshot) != pins['source_manifest_digest']:
            raise StateError('source content differs from approved manifest')
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
    return DevelopmentHost(directory, enabled=True, repair_rounds=pins.get('repair_rounds', 0), **options)
