"""Exact-version transport for signed owner and independent-review receipts."""
from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import asdict, dataclass

from factory_state.model import StateError
from factory_state.scope import canonical
from .intake import IntakePlan

BUCKET = 'tims-software-factory-666730517561-ca-central-1'
MAX_RECEIPT = 16384


def receipt_plan_digest(plan: IntakePlan) -> str:
    if not isinstance(plan, IntakePlan):
        raise StateError('receipt transport requires an exact intake plan')
    lease = asdict(plan.lease); lease['expires_at'] = plan.lease.expires_at.isoformat()
    document = {'schema_version': '1.0', 'factory_id': plan.factory_id, 'task_id': plan.task_id,
        'state': plan.state, 'state_version': plan.state_version, 'lease': lease,
        'request': asdict(plan.request), 'capability_payload': plan.capability_payload,
        'review_payload': plan.review_payload}
    return 'sha256:' + hashlib.sha256(canonical(document)).hexdigest()


@dataclass(frozen=True)
class ReceiptVersions:
    owner: str
    reviewer: str

    def __post_init__(self):
        if any(not isinstance(value, str) or not value or value == 'null' or len(value) > 1024 or any(c.isspace() for c in value)
               for value in (self.owner, self.reviewer)):
            raise StateError('receipt transport requires exact immutable object versions')


@dataclass(frozen=True)
class SignedReceiptBundle:
    plan_digest: str
    owner_signature: bytes
    reviewer_signature: bytes


@dataclass(frozen=True)
class ReceiptPublication:
    plan_digest: str
    signer_identity: str
    key: str
    version_id: str
    checksum_sha256: str


def s3_client(session):
    from botocore.config import Config
    return session.client('s3', region_name='ca-central-1',
        endpoint_url='https://s3.ca-central-1.amazonaws.com',
        config=Config(connect_timeout=5, read_timeout=10,
                      retries={'total_max_attempts': 1, 'mode': 'standard'}))


class VersionedS3ReceiptTransport:
    """Read only two exact, signature-authenticated, versioned receipt objects."""
    def __init__(self, client, *, bucket=BUCKET):
        if bucket != BUCKET:
            raise StateError('scope receipts require the immutable Factory bucket')
        config = getattr(getattr(client, 'meta', None), 'config', None)
        endpoint = getattr(getattr(client, 'meta', None), 'endpoint_url', None)
        if (config is None or endpoint != 'https://s3.ca-central-1.amazonaws.com' or
                config.retries.get('total_max_attempts') != 1):
            raise StateError('receipt transport requires regional S3 with retries disabled')
        self.client, self.bucket = client, bucket

    @staticmethod
    def _json(raw):
        def unique(pairs):
            value = {}
            for key, item in pairs:
                if key in value: raise StateError('duplicate receipt envelope field')
                value[key] = item
            return value
        try: value = json.loads(raw, object_pairs_hook=unique)
        except (TypeError, ValueError) as error: raise StateError('receipt envelope is malformed') from error
        if not isinstance(value, dict): raise StateError('receipt envelope must be an object')
        return value

    def _load(self, plan, version, kind, plan_digest):
        key = f'factory-scope-receipts/{plan_digest.removeprefix("sha256:")}/{kind}.json'
        response = self.client.get_object(Bucket=self.bucket, Key=key, VersionId=version,
                                          ChecksumMode='ENABLED')
        body = response.get('Body')
        try:
            if (response.get('VersionId') != version or response.get('ContentLength', MAX_RECEIPT + 1) > MAX_RECEIPT or
                    response.get('Metadata', {}).get('plan-digest') != plan_digest or body is None):
                raise StateError('versioned receipt object differs from reviewed location')
            raw = body.read(MAX_RECEIPT + 1)
            if len(raw) > MAX_RECEIPT: raise StateError('receipt envelope exceeds limit')
            checksum = base64.b64encode(hashlib.sha256(raw).digest()).decode()
            if response.get('ChecksumSHA256') != checksum:
                raise StateError('receipt object checksum is missing or invalid')
        finally:
            if body is not None: body.close()
        envelope = self._json(raw)
        expected_payload = plan.capability_payload if kind == 'owner' else plan.review_payload
        expected_identity = 'tim_brydges' if kind == 'owner' else plan.review_payload['reviewer_identity']
        if (set(envelope) != {'schema_version','plan_digest','signer_identity','payload','signature_base64'} or
                envelope.get('schema_version') != '1.0' or envelope.get('plan_digest') != plan_digest or
                envelope.get('signer_identity') != expected_identity or envelope.get('payload') != expected_payload):
            raise StateError('receipt envelope binding differs from intake plan')
        try: signature = base64.b64decode(envelope['signature_base64'], validate=True)
        except (KeyError, TypeError, ValueError) as error: raise StateError('receipt signature encoding is invalid') from error
        if len(signature) != 64: raise StateError('receipt signature length is invalid')
        return signature

    def load(self, plan, versions):
        if not isinstance(versions, ReceiptVersions):
            raise StateError('receipt object versions are required')
        plan_digest = receipt_plan_digest(plan)
        owner = self._load(plan, versions.owner, 'owner', plan_digest)
        reviewer = self._load(plan, versions.reviewer, 'reviewer', plan_digest)
        return SignedReceiptBundle(plan_digest, owner, reviewer)


class VersionedS3ReceiptPublisher:
    """Sign and immutably publish one exact owner or reviewer receipt."""

    def __init__(self, client, signer, *, kind, bucket=BUCKET):
        if bucket != BUCKET or kind not in {'owner', 'reviewer'}:
            raise StateError('receipt publisher has an invalid immutable destination')
        config = getattr(getattr(client, 'meta', None), 'config', None)
        endpoint = getattr(getattr(client, 'meta', None), 'endpoint_url', None)
        if (config is None or endpoint != 'https://s3.ca-central-1.amazonaws.com' or
                config.retries.get('total_max_attempts') != 1):
            raise StateError('receipt publisher requires regional S3 with retries disabled')
        if not isinstance(getattr(signer, 'identity', None), str):
            raise StateError('receipt publisher requires an authenticated signer')
        self.client, self.signer = client, signer
        self.kind, self.bucket = kind, bucket

    def publish(self, plan, *, now):
        plan_digest = receipt_plan_digest(plan)
        if self.kind == 'owner':
            payload, expected_identity = plan.capability_payload, 'tim_brydges'
        else:
            payload = plan.review_payload
            expected_identity = payload.get('reviewer_identity')
        if self.signer.identity != expected_identity:
            raise StateError('receipt signer differs from reviewed plan')
        signature = self.signer.sign(payload, now=now)
        if not isinstance(signature, bytes) or len(signature) != 64:
            raise StateError('receipt signer returned an invalid signature')
        envelope = {'schema_version': '1.0', 'plan_digest': plan_digest,
            'signer_identity': expected_identity, 'payload': payload,
            'signature_base64': base64.b64encode(signature).decode('ascii')}
        raw = canonical(envelope)
        if len(raw) > MAX_RECEIPT:
            raise StateError('receipt envelope exceeds limit')
        checksum = base64.b64encode(hashlib.sha256(raw).digest()).decode('ascii')
        key = (f'factory-scope-receipts/{plan_digest.removeprefix("sha256:")}/'
               f'{self.kind}.json')
        response = self.client.put_object(Bucket=self.bucket, Key=key, Body=raw,
            ContentType='application/json', ServerSideEncryption='AES256', IfNoneMatch='*',
            ChecksumSHA256=checksum, Metadata={'plan-digest': plan_digest,
                                               'signer-identity': expected_identity})
        version = response.get('VersionId')
        if (not isinstance(version, str) or not version or version == 'null' or
                len(version) > 1024 or any(character.isspace() for character in version)):
            raise StateError('receipt publication lacks an immutable object version')
        return ReceiptPublication(plan_digest, expected_identity, key, version, checksum)
