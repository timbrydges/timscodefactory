"""Verify signed objective/review receipts before immutable scope writes.

Trusted keys must be configured by the controller, never supplied by the job.
The signed message is canonical JSON. This module does not approve semantics:
an independent reviewer must actually examine the capability/evidence/stop link.
"""
from __future__ import annotations

import base64
import hashlib
import json
import subprocess
import tempfile
from datetime import datetime
from pathlib import Path

from .dispatch import DispatchRequest, DynamoDBDispatchStore
from .model import CONTROLLER_IDENTITY, StateError, TaskState
from .signers import public_key_der


def canonical(payload: dict) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()


class SignedScopeStore:
    def __init__(self, table_name: str, client, trusted_keys: dict[str, bytes], *, openssl='openssl'):
        self.table_name, self.client = table_name, client
        self.trusted_keys = dict(trusted_keys)
        material = [public_key_der(key) for key in self.trusted_keys.values()]
        if len(material) != len(set(material)):
            raise StateError('independent identities cannot share a signing key')
        self.openssl = openssl

    def _verify(self, payload: dict, signature: bytes, identity: str, now: datetime) -> str:
        if now.tzinfo is None or now.utcoffset() is None:
            raise StateError('scope time must be timezone-aware')
        if identity not in self.trusted_keys or not isinstance(signature, bytes) or len(signature) != 64:
            raise StateError('scope signer or signature invalid')
        raw = canonical(payload)
        if len(raw) > 16000:
            raise StateError('scope receipt too large')
        for name in ('issued_at', 'expires_at'):
            if type(payload.get(name)) is not int:
                raise StateError('invalid scope receipt time')
        if not payload['issued_at'] <= now.timestamp() < payload['expires_at']:
            raise StateError('scope receipt expired or future-dated')
        with tempfile.TemporaryDirectory(prefix='factory-scope-') as directory:
            root = Path(directory)
            (root/'key.pem').write_bytes(self.trusted_keys[identity])
            (root/'message').write_bytes(raw)
            (root/'signature').write_bytes(signature)
            result = subprocess.run([self.openssl, 'pkeyutl', '-verify', '-pubin', '-inkey',
                str(root/'key.pem'), '-rawin', '-in', str(root/'message'), '-sigfile',
                str(root/'signature')], capture_output=True, timeout=10, check=False)
        if result.returncode != 0:
            raise StateError('scope signature verification failed')
        return 'sha256:' + hashlib.sha256(raw).hexdigest()

    def _write(self, item: dict) -> None:
        self.client.put_item(TableName=self.table_name, Item=item,
            ConditionExpression='attribute_not_exists(PK) AND attribute_not_exists(SK)')

    def _capability_item(self, state: TaskState, request: DispatchRequest, payload: dict,
                           signature: bytes, *, now: datetime) -> dict:
        expected = {'kind': 'capability', 'factory_id': state.factory_id,
            'objective_id': request.objective_id, 'capability_id': request.capability_id,
            'contract_digest': request.contract_digest, 'owner_identity': 'tim_brydges'}
        if set(payload) != set(expected) | {'issued_at', 'expires_at', 'required_evidence', 'stop_condition'}:
            raise StateError('invalid capability receipt fields')
        if any(payload.get(k) != v for k, v in expected.items()):
            raise StateError('capability receipt binding mismatch')
        for name in ('required_evidence', 'stop_condition'):
            if not isinstance(payload[name], str) or not payload[name].strip() or len(payload[name]) > 2000:
                raise StateError('capability needs bounded evidence and stop criteria')
        digest = self._verify(payload, signature, 'tim_brydges', now)
        return {'signature': {'S': base64.b64encode(signature).decode()}, 'PK': {'S': f'FACTORY#{state.factory_id}#TASK#SCOPE#OBJECTIVE#{request.objective_id}'},
            'SK': {'S': f'CAPABILITY#{request.capability_id}'}, 'status': {'S': 'OPEN'},
            'owner_identity': {'S': 'tim_brydges'}, 'contract_digest': {'S': request.contract_digest},
            'approval_evidence_digest': {'S': digest}, 'expires_at': {'N': str(payload['expires_at'])},
            'signed_payload': {'S': canonical(payload).decode()}}

    def _review_item(self, state: TaskState, request: DispatchRequest, payload: dict,
                     signature: bytes, *, now: datetime) -> dict:
        expected = {'kind': 'scope_review', 'factory_id': state.factory_id, 'task_id': state.task_id,
            'binding': DynamoDBDispatchStore._binding(request), 'verdict': 'ACCEPTED'}
        if set(payload) != set(expected) | {'reviewer_identity', 'issued_at', 'expires_at', 'rationale'}:
            raise StateError('invalid scope review fields')
        if any(payload.get(k) != v for k, v in expected.items()):
            raise StateError('scope review binding mismatch')
        identity = payload.get('reviewer_identity')
        if identity not in {'independent_inspector_service', 'product_spec_reviewer_service'}:
            raise StateError('invalid scope reviewer')
        lease = next((x for x in state.leases if x.lease_id == request.lease_id), None)
        if lease is None or not lease.active_at(now) or identity == lease.authoritative_identity:
            raise StateError('scope reviewer must be independent of an active executor')
        if not isinstance(payload['rationale'], str) or not payload['rationale'].strip() or len(payload['rationale']) > 2000:
            raise StateError('scope review needs bounded rationale')
        digest = self._verify(payload, signature, identity, now)
        return {'signature': {'S': base64.b64encode(signature).decode()}, 'PK': DynamoDBDispatchStore._key(state, request)['PK'],
            'SK': {'S': f'SCOPE#{request.lease_id}'}, 'status': {'S': 'ACCEPTED'},
            'binding': {'S': expected['binding']}, 'reviewer_identity': {'S': identity},
            'review_evidence_digest': {'S': digest}, 'expires_at': {'N': str(payload['expires_at'])},
            'signed_payload': {'S': canonical(payload).decode()}}

    def approve_capability(self, state, request, payload, signature, *, now):
        self._write(self._capability_item(state, request, payload, signature, now=now))

    def approve_task(self, state, request, payload, signature, *, now):
        self._write(self._review_item(state, request, payload, signature, now=now))

    def verify_persisted(self, state, request, *, now):
        """Reverify with current trusted keys; old unsigned rows cannot dispatch workers."""
        keys = [
            {'PK': {'S': f'FACTORY#{state.factory_id}#TASK#SCOPE#OBJECTIVE#{request.objective_id}'},
             'SK': {'S': f'CAPABILITY#{request.capability_id}'}},
            {'PK': DynamoDBDispatchStore._key(state, request)['PK'],
             'SK': {'S': f'SCOPE#{request.lease_id}'}}]
        for key, validate in zip(keys, (self._capability_item, self._review_item)):
            item = self.client.get_item(TableName=self.table_name, Key=key,
                                        ConsistentRead=True).get('Item')
            try:
                payload = json.loads(item['signed_payload']['S'])
                signature = base64.b64decode(item['signature']['S'], validate=True)
                expected = validate(state, request, payload, signature, now=now)
            except (KeyError, TypeError, ValueError) as error:
                raise StateError('persisted scope signature is missing or malformed') from error
            if item != expected:
                raise StateError('persisted scope has changed or is closed')
