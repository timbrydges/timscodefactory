"""Model-free Lambda entry point for the isolated acceptance broker canary.

Deployment can prove the pinned code and event path without reading a provider
secret, claiming a dispatch, or making a model request. Live dispatch remains
unreachable until a separately reviewed entry point is added.
"""
from __future__ import annotations

import json
import os
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path

from factory_state.model import COMMIT_SHA, StateError


_NONCE = re.compile(r'[A-Za-z0-9-]{16,64}')
_FLAG = 'FACTORY_ACCEPTANCE_BROKER_ENABLED'


def _disabled_broker_backend(root: Path, *, source_commit: str) -> None:
    """Compose the packaged broker and provider without granting any IO."""
    from .acceptance_broker_service import AcceptanceBrokerService
    from .acceptance_openai import AcceptanceOpenAIProvider
    from .autonomy import AutonomyActivation
    from .autonomy_contract import load_autonomy_operating_allowance
    from .openai_provider import OpenAIProviderPolicy

    allowance = load_autonomy_operating_allowance(root)
    if (allowance.activation_ready or allowance.production_release_authorized or
            allowance.acceptance_task_id != 'deterministic-text-fingerprint' or
            allowance.target_alias != 'coding_primary_sol_live' or
            allowance.model_id != 'gpt-5.6-sol' or
            allowance.maximum_provider_calls != 3):
        raise StateError('disabled acceptance broker contract differs')

    class NoOperationalIO:
        def __getattr__(self, name):
            raise StateError('disabled broker cannot access operational IO')

    now = datetime.now(timezone.utc)
    activation = AutonomyActivation('disabled-broker-probe', 'tims-software-factory',
        allowance.acceptance_task_id, source_commit,
        'sha256:' + allowance.acceptance_contract_sha256,
        now, now + timedelta(minutes=1))
    inert = NoOperationalIO()
    provider = AcceptanceOpenAIProvider(inert, inert, inert,
        policy=OpenAIProviderPolicy(live_enabled=False))
    service = AcceptanceBrokerService(root, activation, inert, inert, provider,
                                      lambda: now, enabled=False)
    try:
        service.handle({})
    except StateError as error:
        if str(error) != 'acceptance broker is disabled':
            raise
    else:
        raise StateError('acceptance broker unexpectedly enabled')


def handle_probe(event, *, source_commit: str, enabled: str, root: Path | None = None) -> dict:
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
    _disabled_broker_backend(Path(root) if root is not None else Path(__file__).resolve().parents[2],
                             source_commit=source_commit)
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
                        enabled=os.environ.get(_FLAG, ''), root=root)
