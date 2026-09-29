"""Isolated acceptance broker, disabled until deployment and contract gates pass."""
from __future__ import annotations

import json
import os
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path

from factory_state.model import COMMIT_SHA, StateError


_NONCE = re.compile(r'[A-Za-z0-9-]{16,64}')
_FLAG = 'FACTORY_ACCEPTANCE_BROKER_ENABLED'
_ACTIVATION = 'FACTORY_ACCEPTANCE_ACTIVATION_JSON'
_SECRET_ARN = 'FACTORY_OPENAI_SECRET_ARN'


def _disabled_broker_backend(root: Path, *, source_commit: str) -> None:
    """Compose the packaged broker and provider without granting any IO."""
    from .acceptance_broker_service import AcceptanceBrokerService
    from .acceptance_openai import AcceptanceOpenAIProvider
    from .autonomy import AutonomyActivation
    from .autonomy_contract import load_autonomy_operating_allowance
    from .openai_provider import OpenAIProviderPolicy

    allowance = load_autonomy_operating_allowance(root)
    if (allowance.status == 'ACTIVE' or not allowance.pending_gates or
            allowance.production_release_authorized or
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


def _activation(raw: str, *, source_commit: str, root: Path):
    """Accept only deployment-owned activation, never authorization in an event."""
    from .autonomy import AutonomyActivation
    from .autonomy_contract import load_autonomy_operating_allowance

    if not isinstance(raw, str) or not 0 < len(raw) <= 2048:
        raise StateError('broker activation deployment is missing')
    try:
        config = json.loads(raw)
        if not isinstance(config, dict) or set(config) != {
                'activation_id', 'factory_id', 'task_id', 'source_commit',
                'contract_digest', 'starts_at', 'expires_at'}:
            raise ValueError('invalid activation fields')
        activation = AutonomyActivation(config['activation_id'], config['factory_id'],
            config['task_id'], config['source_commit'], config['contract_digest'],
            datetime.fromisoformat(config['starts_at']), datetime.fromisoformat(config['expires_at']))
    except (ValueError, TypeError, KeyError) as error:
        raise StateError('broker activation deployment is invalid') from error
    allowance = load_autonomy_operating_allowance(root)
    now = datetime.now(timezone.utc)
    if (not allowance.activation_ready or allowance.production_release_authorized or
            activation.factory_id != 'tims-software-factory' or
            activation.task_id != allowance.acceptance_task_id or
            activation.source_commit != source_commit or
            activation.contract_digest != 'sha256:' + allowance.acceptance_contract_sha256 or
            not allowance.pricing_observed_at <= now < allowance.pricing_expires_at):
        raise StateError('broker activation differs from approved deployment')
    activation.validate(now)
    return activation


def handle_live(event, *, source_commit: str, activation_json: str,
                secret_arn: str, root: Path, database, secrets, transport):
    """One claimed and budgeted call; credential access belongs only to this broker."""
    from .acceptance_broker_service import AcceptanceBrokerService
    from .acceptance_budget import DynamoDBAcceptanceBudgetStore
    from .acceptance_claim import DynamoDBAcceptanceClaimStore
    from .acceptance_openai import AcceptanceOpenAIProvider
    from .acceptance_provider_io import AcceptanceContractPricingSource
    from .openai_provider import OpenAIProviderPolicy
    from .provider_credentials import SecretsManagerProviderCredentialLeaseSource

    activation = _activation(activation_json, source_commit=source_commit, root=root)
    if not isinstance(secret_arn, str):
        raise StateError('broker secret binding is missing')
    try:
        credential_source = SecretsManagerProviderCredentialLeaseSource(secrets, secret_arn)
    except ValueError as error:
        raise StateError('broker secret binding is invalid') from error
    provider = AcceptanceOpenAIProvider(credential_source,
        AcceptanceContractPricingSource(root), transport,
        policy=OpenAIProviderPolicy(live_enabled=True))
    service = AcceptanceBrokerService(root, activation,
        DynamoDBAcceptanceBudgetStore('tims-factory-acceptance-budget', database),
        DynamoDBAcceptanceClaimStore('tims-factory-acceptance-broker-claims', database),
        provider, lambda: datetime.now(timezone.utc), enabled=True)
    return service.handle(event)


def handler(event, context):
    root = Path(os.environ.get('LAMBDA_TASK_ROOT', '/var/task'))
    try:
        build = json.loads((root / 'BUILD.json').read_text(encoding='utf-8'))
        if not isinstance(build, dict) or set(build) != {'source_commit'}:
            raise ValueError('invalid build')
    except (OSError, ValueError, TypeError) as exc:
        raise StateError('acceptance broker build identity is invalid') from exc
    enabled = os.environ.get(_FLAG, '')
    if enabled == 'false':
        return handle_probe(event, source_commit=build['source_commit'],
                            enabled=enabled, root=root)
    if enabled != 'true':
        raise StateError('acceptance broker kill switch is invalid')
    activation_json = os.environ.get(_ACTIVATION, '')
    _activation(activation_json, source_commit=build['source_commit'], root=root)
    if not isinstance(event, dict) or event.get('kind') != 'acceptance_provider_call':
        raise StateError('broker live event kind is invalid')
    import boto3
    from botocore.config import Config
    from .acceptance_provider_io import AcceptanceOpenAIHTTPTransport
    from .provider_credentials import secrets_manager_client
    session = boto3.Session(region_name='ca-central-1')
    database = session.client('dynamodb', config=Config(connect_timeout=3,
        read_timeout=5, retries={'total_max_attempts': 1, 'mode': 'standard'}))
    return handle_live(event, source_commit=build['source_commit'],
        activation_json=activation_json, secret_arn=os.environ.get(_SECRET_ARN, ''),
        root=root, database=database, secrets=secrets_manager_client(session),
        transport=AcceptanceOpenAIHTTPTransport())
