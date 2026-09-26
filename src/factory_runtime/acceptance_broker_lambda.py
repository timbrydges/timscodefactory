"""Model-free Lambda entry point for the isolated acceptance broker canary.

Deployment can prove the pinned code and event path without reading a provider
secret, claiming a dispatch, or making a model request. Live dispatch remains
unreachable until a separately reviewed entry point is added.
"""
from __future__ import annotations

import json
import os
import re
from pathlib import Path

from factory_state.model import COMMIT_SHA, StateError


_NONCE = re.compile(r'[A-Za-z0-9-]{16,64}')
_FLAG = 'FACTORY_ACCEPTANCE_BROKER_ENABLED'


def handle_probe(event, *, source_commit: str, enabled: str) -> dict:
    if enabled != 'false':
        raise StateError('acceptance broker kill switch must remain false')
    if (not isinstance(source_commit, str) or not COMMIT_SHA.fullmatch(source_commit) or
            not isinstance(event, dict) or set(event) !=
            {'kind', 'source_commit', 'nonce', 'task_id'} or
            event.get('kind') != 'acceptance_broker_probe' or
            event.get('source_commit') != source_commit or
            event.get('task_id') != 'deterministic-text-fingerprint' or
            not isinstance(event.get('nonce'), str) or
            not _NONCE.fullmatch(event['nonce'])):
        raise StateError('invalid acceptance broker deployment probe')
    return {'kind': 'acceptance_broker_probe_result', 'source_commit': source_commit,
            'nonce': event['nonce'], 'task_id': event['task_id'],
            'broker_enabled': False, 'provider_calls': 0,
            'credentials_read': False, 'release_dispatched': False}


def handler(event, context):
    root = Path(os.environ.get('LAMBDA_TASK_ROOT', '/var/task'))
    try:
        build = json.loads((root / 'BUILD.json').read_text(encoding='utf-8'))
        if not isinstance(build, dict) or set(build) != {'source_commit'}:
            raise ValueError('invalid build')
    except (OSError, ValueError, TypeError) as exc:
        raise StateError('acceptance broker build identity is invalid') from exc
    return handle_probe(event, source_commit=build['source_commit'],
                        enabled=os.environ.get(_FLAG, ''))
