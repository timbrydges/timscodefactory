"""Read-only live scope gate for disabled configuration staging."""
from __future__ import annotations

import json
from datetime import datetime

from prepare_acceptance_activation_bundle import build_activation_bundle
from prepare_acceptance_job import BINDING_FIELDS, PLAN_FIELDS
from prepare_role_deployment import ACCOUNT, REGION, ROOT, source
from publish_acceptance_job import verified_job
from factory_runtime.acceptance_jobs import PinnedJobVersion, VersionedS3AcceptanceJobSource, _unique
from factory_runtime.autonomy import AutonomyActivation
from factory_runtime.receipt_transport import s3_client
from factory_runtime.worker import digest
from factory_state.dynamodb import DynamoDBStateStore
from factory_state.model import StateError


def verify_scope(binding, raw, *, commit, now, s3, states, database, root=ROOT):
    bundle = build_activation_bundle(binding, raw, root=root, now=now)
    document = json.loads(raw, object_pairs_hook=_unique)
    expected, proof = verified_job(
        {key: binding[key] for key in BINDING_FIELDS},
        {key: document[key] for key in PLAN_FIELDS}, document['receipt_versions'],
        commit=commit, now=now, s3=s3, states=states, database=database, root=root)
    if raw != expected:
        raise StateError('staging job differs from the exact verified publication bytes')
    activation = AutonomyActivation(binding['activation_id'], document['factory_id'],
        document['task_id'], commit, binding['contract_digest'],
        datetime.fromisoformat(binding['starts_at']), datetime.fromisoformat(binding['expires_at']))
    state = states.load_state(activation.factory_id, activation.task_id)
    if state is None or state.version != proof['task_state_version'] or any(lease.active_at(now) for lease in state.leases):
        raise StateError('authoritative task changed during staging verification')
    # Read the actual immutable object through the runtime decoder. Local bytes
    # and a syntactically valid version name are not publication evidence.
    VersionedS3AcceptanceJobSource(s3, activation, {'IMPLEMENTATION':
        PinnedJobVersion(binding['job_version_id'], digest(raw))}).load(
            activation.factory_id, activation.task_id, state)
    return {'status': 'LIVE_SCOPE_VERIFIED_FOR_DISABLED_STAGING', **proof,
        'job_version_id': binding['job_version_id'],
        'contract_blockers': bundle['contract_blockers'],
        'activation_authorized': False, 'model_calls': 0}


def verify_live_scope(binding, raw, *, now):
    import boto3
    from botocore.config import Config

    commit = source()
    session = boto3.Session(region_name=REGION)
    config = Config(connect_timeout=5, read_timeout=10,
                    retries={'total_max_attempts': 1, 'mode': 'standard'})
    if session.client('sts', config=config).get_caller_identity()['Account'] != ACCOUNT:
        raise StateError('wrong AWS account')
    database = session.client('dynamodb', config=config)
    return verify_scope(binding, raw, commit=commit, now=now, s3=s3_client(session),
        states=DynamoDBStateStore('tims-software-factory-state', database), database=database)
