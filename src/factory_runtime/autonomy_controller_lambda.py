"""Inert acceptance scheduler target, pending a separately reviewed runtime."""
import json
import os
import re
from pathlib import Path

from factory_state.model import StateError


def handler(event, context):
    root = Path(os.environ.get('LAMBDA_TASK_ROOT', '/var/task'))
    commit = json.loads((root / 'BUILD.json').read_text(encoding='utf-8'))['source_commit']
    if os.environ.get('FACTORY_AUTONOMY_CONTROLLER_ENABLED') != 'false':
        raise StateError('acceptance controller deployment is not disabled')
    if (not isinstance(event, dict) or set(event) != {'kind', 'source_commit', 'nonce', 'task_id'} or
            event.get('kind') != 'disabled_controller_probe' or
            event.get('source_commit') != commit or
            event.get('task_id') != 'deterministic-text-fingerprint' or
            not isinstance(event.get('nonce'), str) or
            not re.fullmatch(r'[a-f0-9]{32}', event['nonce'])):
        raise StateError('acceptance controller accepts only the disabled deployment probe')
    return {'kind': 'disabled_controller_probe_result', 'source_commit': commit,
            'nonce': event['nonce'], 'task_id': event['task_id'],
            'controller_enabled': False, 'schedule_enabled': False,
            'model_calls': 0, 'release_dispatched': False}
