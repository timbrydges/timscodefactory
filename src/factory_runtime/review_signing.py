"""Disabled-by-default, deployment-owned signing for fresh bounded review only."""
import copy
import re
import threading
from datetime import datetime, timezone

from factory_state.dispatch import DispatchRequest, DynamoDBDispatchStore
from factory_state.kms_signer import ALGORITHM, public_pem
from factory_state.model import SHA256_DIGEST, StateError
from factory_state.scope import SignedScopeStore, canonical
from .cloud_roles import ROLE_IDENTITIES
from .review_provider_scope import FACTORY, TASK, ProviderScope, validate_unsigned

KEYS = {
    'owner': 'arn:aws:kms:ca-central-1:666730517561:key/4cdc8470-77f4-4c5a-a772-7b379f34fbbb',
    'builder': 'arn:aws:kms:ca-central-1:666730517561:key/9c24941f-563b-4dc9-bcc3-394384c655eb',
    'inspector': 'arn:aws:kms:ca-central-1:666730517561:key/7885556b-627c-4d95-a635-8849477fc00e',
    'qa': 'arn:aws:kms:ca-central-1:666730517561:key/71cb555e-37e8-44ec-b638-86072e3231c6'}
ROLES = {name: 'tims-factory-signing-' + name for name in ('owner', 'builder', 'inspector')}
ROLES['qa'] = 'tims-factory-review-qa'


class _EnrolledSigner:
    key_bindings = KEYS
    role_bindings = ROLES
    identities = {'owner': 'tim_brydges', **{r: ROLE_IDENTITIES[r] for r in ('builder', 'inspector', 'qa')}}

    def __init__(self, *, role, kms, sts, key_loader, clock=None, enabled=False):
        if (role not in self.key_bindings or type(enabled) is not bool or not callable(key_loader) or
                (clock is not None and not callable(clock))):
            raise StateError('deployment-owned signing configuration required')
        self.role, self.kms, self.sts, self.key_loader = role, kms, sts, key_loader
        self.clock = clock or (lambda: datetime.now(timezone.utc))
        self.enabled, self.attempted = enabled, False
        self._lock = threading.Lock()
        self.identity = self.identities[role]

    def _session(self):
        value = self.sts.get_caller_identity()
        prefix = 'arn:aws:sts::666730517561:assumed-role/' + self.role_bindings[self.role] + '/'
        arn = value.get('Arn', '')
        if (value.get('Account') != '666730517561' or type(arn) is not str or
                not arn.startswith(prefix) or not arn[len(prefix):] or '/' in arn[len(prefix):]):
            raise StateError('fresh signing role session differs')
        return arn

    def _check(self, payload, now):
        raise NotImplementedError

    def _keys(self, now):
        keys = self.key_loader(now)
        if self.identity not in keys:
            raise StateError('signing enrollment expired or revoked')
        SignedScopeStore('unused', None, keys)  # Reject shared identity keys before KMS.
        return dict(keys)

    def sign(self, payload, *, now):
        with self._lock:
            return self._sign_once(payload, now=now)

    def _sign_once(self, payload, *, now):
        if not self.enabled or self.attempted:
            raise StateError('fresh signer disabled or attempt already consumed')
        payload = copy.deepcopy(payload)
        self._check(payload, now)
        current = self.clock()
        self._check(payload, current)
        keys = self._keys(current)
        raw = canonical(payload)
        if len(raw) > 4096:
            raise StateError('KMS RAW signing limit exceeded')
        # Once remote work starts, an unknown outcome must not trigger a local retry.
        self.attempted = True
        session = self._session()
        key = self.key_bindings[self.role]
        pem = public_pem(self.kms.get_public_key(KeyId=key), expected_arn=key)
        if pem != keys[self.identity]:
            raise StateError('KMS public key differs from active enrollment')
        if self._session() != session:
            raise StateError('signing session changed')
        current = self.clock()
        self._check(payload, current)
        if self._keys(current).get(self.identity) != pem:
            raise StateError('signing enrollment changed before signature')
        result = self.kms.sign(KeyId=key, Message=raw, MessageType='RAW', SigningAlgorithm=ALGORITHM)
        if result.get('KeyId') != key or result.get('SigningAlgorithm') != ALGORITHM:
            raise StateError('KMS signature response binding differs')
        current = self.clock()
        self._check(payload, current)
        keys = self._keys(current)
        if keys.get(self.identity) != pem:
            raise StateError('signing enrollment changed after signature')
        signature = result.get('Signature')
        SignedScopeStore('unused', None, keys)._verify(payload, signature, self.identity, current)
        return signature


class ReviewAllowanceSigner(_EnrolledSigner):
    """Only an authenticated owner workflow supplies qualified deployment context.

    This validates exact scope and caps; it does not authenticate pricing or
    readiness evidence authors. The owner workflow must do that before enabling.
    """
    def __init__(self, *, scope, pricing, readiness, **kwargs):
        if type(scope) is not ProviderScope:
            raise StateError('exact fresh provider scope required')
        self.scope, self.pricing, self.readiness = copy.deepcopy((scope, pricing, readiness))
        self.scope.bindings()
        super().__init__(role='owner', **kwargs)

    def _check(self, payload, now):
        validate_unsigned(payload, scope=self.scope, pricing=self.pricing,
                          readiness=self.readiness, now=now)


class ReviewRoleResultSigner(_EnrolledSigner):
    """RoleExecutionService supplies output digests after guarded provider execution.

    A signature attests result origin, not ACCEPTED semantics. Progression still
    requires deployment-owned test proof and verdict validation.
    """
    def __init__(self, *, role, request, dispatch_id, **kwargs):
        if (role not in {'builder', 'inspector', 'qa'} or type(request) is not DispatchRequest or
                type(dispatch_id) is not str or not re.fullmatch(r'[a-f0-9]{64}', dispatch_id)):
            raise StateError('exact fresh role request and dispatch required')
        self.expected = {'kind': 'role_result', 'factory_id': FACTORY, 'task_id': TASK,
            'binding': DynamoDBDispatchStore._binding(request), 'dispatch_id': dispatch_id,
            'producer_identity': ROLE_IDENTITIES[role]}
        super().__init__(role=role, **kwargs)

    def preflight(self):
        """Read-only custody check before provider work; grants no signing authority."""
        with self._lock:
            if not self.enabled or self.attempted:
                raise StateError('fresh signer disabled or attempt already consumed')
            keys = self._keys(self.clock())
            session = self._session()
            pem = public_pem(self.kms.get_public_key(KeyId=self.key_bindings[self.role]),
                             expected_arn=self.key_bindings[self.role])
            if (pem != keys[self.identity] or self._session() != session or
                    self._keys(self.clock()).get(self.identity) != pem):
                raise StateError('signing custody or enrollment changed during preflight')
            return self.identity

    def _check(self, payload, now):
        if (type(now) is not datetime or now.tzinfo is None or now.utcoffset() is None or
                type(payload) is not dict or set(payload) != set(self.expected) |
                {'output_digest', 'issued_at', 'expires_at'} or
                any(type(payload[k]) is not type(v) or payload[k] != v for k, v in self.expected.items()) or
                type(payload['output_digest']) is not str or not SHA256_DIGEST.fullmatch(payload['output_digest']) or
                type(payload['issued_at']) is not int or type(payload['expires_at']) is not int or
                not payload['issued_at'] <= now.timestamp() < payload['expires_at'] <= payload['issued_at'] + 300):
            raise StateError('fresh role result bindings or lifetime differ')
