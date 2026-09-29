"""Read only deployment-pinned, versioned acceptance jobs from regional S3.

Jobs carry an exact intake plan and two receipt version IDs. They cannot sign
scope, grant approval, choose a role endpoint, or authorize provider spending.
"""
from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import asdict, dataclass
from datetime import datetime

from factory_state.dispatch import DispatchRequest
from factory_state.model import Lease, SHA256_DIGEST, StateError, TaskState
from factory_state.scope import canonical

from .autonomy import AutonomyActivation, ScheduledAutonomyJob
from .intake import IntakePlan, STATE_ROLES
from .receipt_transport import BUCKET, ReceiptVersions, receipt_plan_digest
from .worker import digest

MAX_JOB = 192 * 1024
MAX_INPUT = 42020
MAX_CONTRACT = 65536
FIELDS = {'schema_version', 'activation_id', 'factory_id', 'task_id', 'state',
          'state_version', 'lease', 'request', 'capability_payload', 'review_payload',
          'receipt_versions', 'plan_digest', 'input_base64', 'contract_base64'}


@dataclass(frozen=True)
class PinnedJobVersion:
    version_id: str
    sha256: str

    def __post_init__(self):
        if (not isinstance(self.version_id, str) or not self.version_id or
                self.version_id == 'null' or len(self.version_id) > 1024 or
                any(c.isspace() for c in self.version_id) or
                not isinstance(self.sha256, str) or
                not SHA256_DIGEST.fullmatch(self.sha256)):
            raise StateError('acceptance job requires an exact object version and digest')


def encode_job(job: ScheduledAutonomyJob, activation_id: str) -> bytes:
    """Canonical staging bytes; publication and signatures stay with separate roles."""
    if not isinstance(job, ScheduledAutonomyJob) or not isinstance(job.plan, IntakePlan):
        raise StateError('acceptance job requires an exact intake plan')
    plan = job.plan
    lease = asdict(plan.lease)
    lease['expires_at'] = plan.lease.expires_at.isoformat()
    return canonical({'schema_version': '1.0', 'activation_id': activation_id,
        'factory_id': plan.factory_id, 'task_id': plan.task_id, 'state': plan.state,
        'state_version': plan.state_version, 'lease': lease,
        'request': asdict(plan.request), 'capability_payload': plan.capability_payload,
        'review_payload': plan.review_payload, 'plan_digest': receipt_plan_digest(plan),
        'receipt_versions': asdict(job.receipt_versions),
        'input_base64': base64.b64encode(job.input_bytes).decode('ascii'),
        'contract_base64': base64.b64encode(job.contract_bytes).decode('ascii')})


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise StateError('duplicate acceptance job field')
        result[key] = value
    return result


def _decode(value, maximum):
    if not isinstance(value, str) or len(value) > ((maximum + 2) // 3) * 4:
        raise StateError('acceptance job bytes exceed the approved bound')
    try:
        raw = base64.b64decode(value, validate=True)
    except (ValueError, TypeError) as error:
        raise StateError('acceptance job bytes are malformed') from error
    if len(raw) > maximum:
        raise StateError('acceptance job bytes exceed the approved bound')
    return raw


class VersionedS3AcceptanceJobSource:
    """Stage-to-version map belongs to the deployment, never the tick event."""

    def __init__(self, client, activation: AutonomyActivation,
                 versions: dict[str, PinnedJobVersion], *, bucket=BUCKET):
        config = getattr(getattr(client, 'meta', None), 'config', None)
        endpoint = getattr(getattr(client, 'meta', None), 'endpoint_url', None)
        if (bucket != BUCKET or config is None or
                endpoint != 'https://s3.ca-central-1.amazonaws.com' or
                config.retries.get('total_max_attempts') != 1):
            raise StateError('acceptance job source requires no-retry regional S3')
        if (not isinstance(activation, AutonomyActivation) or
                not isinstance(versions, dict) or not versions or
                any(state not in STATE_ROLES or not isinstance(pin, PinnedJobVersion)
                    for state, pin in versions.items())):
            raise StateError('acceptance job source lacks exact deployment pins')
        self.client, self.activation = client, activation
        self.versions, self.bucket = dict(versions), bucket

    def load(self, factory_id: str, task_id: str, state: TaskState) -> ScheduledAutonomyJob:
        if (not isinstance(state, TaskState) or
                (factory_id, task_id) != (self.activation.factory_id, self.activation.task_id) or
                (state.factory_id, state.task_id) != (factory_id, task_id) or
                state.state not in self.versions):
            raise StateError('acceptance job stage differs from deployment')
        pin = self.versions[state.state]
        key = f'factory-autonomy-jobs/{self.activation.activation_id}/{state.state}.json'
        response = self.client.get_object(Bucket=self.bucket, Key=key,
            VersionId=pin.version_id, ChecksumMode='ENABLED')
        body = response.get('Body')
        try:
            size = response.get('ContentLength')
            if (response.get('VersionId') != pin.version_id or
                    type(size) is not int or not 0 < size <= MAX_JOB or body is None):
                raise StateError('acceptance job object differs from pinned version')
            raw = body.read(MAX_JOB + 1)
            if len(raw) != size:
                raise StateError('acceptance job object size differs from pinned version')
            sha = hashlib.sha256(raw).digest()
            if (response.get('ChecksumSHA256') != base64.b64encode(sha).decode('ascii') or
                    pin.sha256 != 'sha256:' + sha.hex()):
                raise StateError('acceptance job object digest differs from deployment')
        finally:
            if body is not None:
                body.close()
        try:
            document = json.loads(raw, object_pairs_hook=_unique)
        except (ValueError, UnicodeError, TypeError) as error:
            raise StateError('acceptance job is malformed') from error
        if (not isinstance(document, dict) or set(document) != FIELDS or
                document['schema_version'] != '1.0' or
                document['activation_id'] != self.activation.activation_id or
                (document['factory_id'], document['task_id'], document['state']) !=
                (factory_id, task_id, state.state) or
                type(document['state_version']) is not int or
                not isinstance(document['capability_payload'], dict) or
                not isinstance(document['review_payload'], dict) or
                not isinstance(document['lease'], dict) or
                set(document['lease']) != set(Lease.__dataclass_fields__) or
                not isinstance(document['request'], dict) or
                set(document['request']) != set(DispatchRequest.__dataclass_fields__) or
                not isinstance(document['receipt_versions'], dict) or
                set(document['receipt_versions']) != {'owner', 'reviewer'}):
            raise StateError('acceptance job binding differs from reviewed stage')
        try:
            lease = Lease(**{**document['lease'], 'expires_at':
                datetime.fromisoformat(document['lease']['expires_at'])})
            request = DispatchRequest(**document['request'])
            versions = ReceiptVersions(**document['receipt_versions'])
        except (ValueError, TypeError, KeyError) as error:
            raise StateError('acceptance job plan is malformed') from error
        plan = IntakePlan(factory_id, task_id, state.state, document['state_version'],
            lease, request, document['capability_payload'], document['review_payload'])
        input_bytes = _decode(document['input_base64'], MAX_INPUT)
        contract_bytes = _decode(document['contract_base64'], MAX_CONTRACT)
        if (document['plan_digest'] != receipt_plan_digest(plan) or
                request.lease_id != lease.lease_id or
                lease.role_id != STATE_ROLES[state.state] or
                request.source_commit != self.activation.source_commit or
                request.input_digest != digest(input_bytes) or
                request.contract_digest != digest(contract_bytes) or
                request.contract_digest != self.activation.contract_digest):
            raise StateError('acceptance job content differs from reviewed activation')
        return ScheduledAutonomyJob(plan, versions, input_bytes, contract_bytes)
