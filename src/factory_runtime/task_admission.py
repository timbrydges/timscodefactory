"""Verify owner-authenticated queue admission; never sign or grant execution.

Only deployment-owned key loaders/resolvers are trusted. Receipts grant admission
to an offline development plan, not provider calls, spending or state progression.
"""
import base64
from dataclasses import asdict
from datetime import datetime
import json

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from factory_state.model import OWNER_IDENTITY, SAFE_IDENTIFIER, StateError
from factory_state.scope import canonical
from factory_state.signers import public_key_der
from .worker import digest


def plan_binding(plan_id, repository, target_commit, contract_bytes, tasks):
    return {'plan_id': plan_id, 'repository': repository, 'target_commit': target_commit,
            'contract_digest': digest(contract_bytes), 'tasks': [asdict(t) for t in tasks]}


class OwnerAdmissionVerifier:
    """key_loader(now) must return only currently enrolled, unrevoked public keys."""
    def __init__(self, key_loader):
        self.key_loader = key_loader

    def verify(self, payload, signature, now):
        pem = self.key_loader(now).get(OWNER_IDENTITY)
        if pem is None or not isinstance(signature, bytes) or len(signature) != 64:
            raise StateError('owner admission key or signature unavailable')
        try:
            Ed25519PublicKey.from_public_bytes(public_key_der(pem)[-32:]).verify(signature, canonical(payload))
        except (InvalidSignature, ValueError) as error:
            raise StateError('owner admission signature invalid') from error


class AuthenticatedTaskAdmission:
    def __init__(self, queue, *, verifier, clock):
        self.queue, self.verifier, self.clock = queue, verifier, clock

    def _verify(self, payload, signature):
        now = self.clock()
        fields = {'kind', 'owner', 'receipt_id', 'issued_at', 'expires_at', 'plan',
                  'execution_authorized', 'spending_authorized', 'signing_authorized', 'release_authorized'}
        if (type(payload) is not dict or set(payload) != fields
                or payload['kind'] != 'factory_queue_admission_v1' or payload['owner'] != OWNER_IDENTITY
                or not isinstance(payload['receipt_id'], str) or not SAFE_IDENTIFIER.fullmatch(payload['receipt_id'])
                or not isinstance(now, datetime) or now.tzinfo is None or now.utcoffset() is None
                or type(payload['issued_at']) is not int or type(payload['expires_at']) is not int
                or not 0 < payload['expires_at'] - payload['issued_at'] <= 86400
                or not payload['issued_at'] <= now.timestamp() < payload['expires_at']
                or any(payload[k] is not False for k in fields if k.endswith('_authorized'))
                or len(canonical(payload)) > 32000):
            raise StateError('invalid or expired queue-only admission')
        self.verifier.verify(payload, signature, now)

    def admit(self, payload, signature, *, plan_id, repository, target_commit, contract_bytes, tasks):
        # Freeze caller objects across verification and persistence.
        payload = json.loads(canonical(payload))
        tasks = tuple(tasks)
        expected = plan_binding(plan_id, repository, target_commit, contract_bytes, tasks)
        if payload.get('plan') != expected:
            raise StateError('admission differs from exact task plan')
        self._verify(payload, signature)
        receipt = json.dumps({'payload': payload, 'signature': base64.b64encode(signature).decode('ascii')}, sort_keys=True)
        self.queue.enqueue_plan(plan_id, repository=repository, target_commit=target_commit,
            contract_bytes=contract_bytes, tasks=tasks, admission=(payload['receipt_id'], receipt))

    def scheduler_resolver(self, trusted_resolver):
        """Recheck expiry/revocation before resolution; existing scheduler gates remain."""
        def resolve(task):
            receipt = self.queue.admission_for(task)
            payload = receipt['payload']
            if asdict(task) not in payload['plan']['tasks']:
                raise StateError('queue entry differs from authenticated plan')
            signature = base64.b64decode(receipt['signature'], validate=True)
            self._verify(payload, signature)
            return trusted_resolver(task)
        return resolve
