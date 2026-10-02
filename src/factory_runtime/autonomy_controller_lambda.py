"""Acceptance scheduler target; deployed template keeps the live branch disabled."""
import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path

from factory_state.model import StateError

ENABLED = 'FACTORY_AUTONOMY_CONTROLLER_ENABLED'
ACTIVATION_CONFIG = 'FACTORY_ACCEPTANCE_CONTROLLER_JSON'


def _controller_activation(root, commit, raw, now):
    """Read exact deployment-owned binding before making any AWS client."""
    from .acceptance_jobs import PinnedJobVersion
    from .autonomy import AutonomyActivation
    from .autonomy_contract import load_autonomy_operating_allowance
    from .cloud_roles import FUNCTION

    if not isinstance(raw, str) or not 0 < len(raw) <= 3500:
        raise StateError('acceptance controller deployment is missing')
    try:
        config = json.loads(raw)
        fields = {'activation_id', 'factory_id', 'task_id', 'source_commit',
                  'contract_digest', 'starts_at', 'expires_at',
                  'builder_version_arn', 'job_versions'}
        if not isinstance(config, dict) or set(config) != fields:
            raise ValueError('invalid controller deployment fields')
        activation = AutonomyActivation(config['activation_id'], config['factory_id'],
            config['task_id'], config['source_commit'], config['contract_digest'],
            datetime.fromisoformat(config['starts_at']),
            datetime.fromisoformat(config['expires_at']))
        raw_versions = config['job_versions']
        if (not isinstance(raw_versions, dict) or set(raw_versions) != {'IMPLEMENTATION'} or
                not isinstance(raw_versions['IMPLEMENTATION'], dict) or
                set(raw_versions['IMPLEMENTATION']) != {'version_id', 'sha256'}):
            raise ValueError('invalid controller job pins')
        versions = {'IMPLEMENTATION': PinnedJobVersion(**raw_versions['IMPLEMENTATION'])}
        builder_arn = config['builder_version_arn']
    except (ValueError, TypeError, KeyError) as error:
        raise StateError('acceptance controller deployment is invalid') from error
    allowance = load_autonomy_operating_allowance(root)
    match = FUNCTION.fullmatch(builder_arn) if isinstance(builder_arn, str) else None
    if (not allowance.permits_activation(activation) or allowance.production_release_authorized or
            activation.factory_id != 'tims-software-factory' or
            activation.task_id != allowance.acceptance_task_id or
            activation.source_commit != commit or
            activation.contract_digest != 'sha256:' + allowance.acceptance_contract_sha256 or
            match is None or match.group(1) != 'builder'):
        raise StateError('acceptance controller deployment differs from owner allowance')
    activation.validate(now)
    if not allowance.pricing_observed_at <= now < allowance.pricing_expires_at:
        raise StateError('acceptance controller pricing is stale')
    return activation, builder_arn, versions


def _controller_service(root, commit, activation, builder_arn, versions,
                        database, s3, lambda_api, *, clock):
    """Construct without IO; authorization remains checked at each effect."""
    from factory_state.dispatch import DynamoDBDispatchStore
    from factory_state.dynamodb import DynamoDBStateStore
    from factory_state.signers import load_trusted_signers
    from .acceptance_budget import DynamoDBAcceptanceBudgetStore
    from .acceptance_controller import AcceptanceController
    from .acceptance_jobs import VersionedS3AcceptanceJobSource
    from .autonomy import AutonomousCycle, AutonomousScheduler
    from .cloud_roles import LambdaRoleExecutor
    from .intake import AuthenticatedIntakeService
    from .operational_backend import AcceptanceOperationalBackend
    from .progression import SignedResultProgressor
    from .receipt_transport import VersionedS3ReceiptTransport
    from .worker import DispatchWorker

    class NoProviderExecution:
        def execute(self, **_):
            raise StateError('controller cannot execute a provider call')

    table = 'tims-software-factory-state'
    states = DynamoDBStateStore(table, database)
    ledger = DynamoDBDispatchStore(table, database)
    key_loader = lambda now: load_trusted_signers(
        root/'factory/profiles/scope-signers.json', now=now)
    budget = DynamoDBAcceptanceBudgetStore('tims-factory-acceptance-budget', database)
    guard = AcceptanceOperationalBackend(root, activation, budget,
        NoProviderExecution(), enabled=True, clock=clock)
    executor = LambdaRoleExecutor(lambda_api, function_arn=builder_arn,
        worker_id='acceptance-controller', guard=guard)
    intake = AuthenticatedIntakeService(states, ledger, key_loader=key_loader, clock=clock)
    worker = DispatchWorker(states, ledger, deployed_commit=commit,
        worker_id='acceptance-controller', key_loader=key_loader,
        executors={'engineering_agent': executor}, clock=clock)
    progressor = SignedResultProgressor(states, ledger, key_loader=key_loader, clock=clock)
    receipts = VersionedS3ReceiptTransport(s3)
    jobs = VersionedS3AcceptanceJobSource(s3, activation, versions)
    cycle = AutonomousCycle(intake, worker, progressor, receipts, enabled=True)
    scheduler = AutonomousScheduler(cycle, states, jobs, activation,
        clock=clock, enabled=True)
    return AcceptanceController(root, activation, scheduler,
        deployed_commit=commit, clock=clock, enabled=True)


def handler(event, context):
    root = Path(os.environ.get('LAMBDA_TASK_ROOT', '/var/task'))
    commit = json.loads((root / 'BUILD.json').read_text(encoding='utf-8'))['source_commit']
    flag = os.environ.get(ENABLED)
    if flag == 'true':
        if event != {'factory_id': 'tims-software-factory',
                     'task_id': 'deterministic-text-fingerprint', 'mode': 'acceptance'}:
            raise StateError('acceptance controller event differs from the exact task')
        now = datetime.now(timezone.utc)
        activation, builder_arn, versions = _controller_activation(
            root, commit, os.environ.get(ACTIVATION_CONFIG), now)
        import boto3
        from botocore.config import Config
        from .cloud_roles import lambda_client
        from .receipt_transport import s3_client
        config = Config(connect_timeout=5, read_timeout=10,
            retries={'total_max_attempts': 1, 'mode': 'standard'})
        session = boto3.Session(region_name='ca-central-1')
        service = _controller_service(root, commit, activation, builder_arn, versions,
            session.client('dynamodb', region_name='ca-central-1', config=config),
            s3_client(session), lambda_client(session),
            clock=lambda: datetime.now(timezone.utc))
        return service.tick(event)
    if flag != 'false':
        raise StateError('acceptance controller deployment is not disabled')
    from .inspection_completion import ENABLED as COMPLETION_ENABLED
    if os.environ.get(COMPLETION_ENABLED) == 'true':
        from .inspection_completion import InspectionCompletion, validate_event, validate_bundle
        from factory_state.dynamodb import DynamoDBStateStore
        validate_event(event, commit)
        now = datetime.now(timezone.utc)
        validate_bundle(root, now)
        import boto3
        from botocore.config import Config
        database = boto3.client('dynamodb', region_name='ca-central-1',
            config=Config(connect_timeout=5, read_timeout=10,
                retries={'total_max_attempts': 1, 'mode': 'standard'}))
        return InspectionCompletion(root, DynamoDBStateStore('tims-software-factory-state', database),
            clock=lambda: datetime.now(timezone.utc)).complete()
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
