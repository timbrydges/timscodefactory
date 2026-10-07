"""Disabled security-only adapters for existing isolated signing identities."""
import copy
import re
from factory_state.dispatch import DispatchRequest, DynamoDBDispatchStore
from factory_state.model import StateError
from .review_signing import _EnrolledSigner, ReviewRoleResultSigner, KEYS, ROLES
from .security_provider_scope import SecurityProviderScope, validate_unsigned

SECURITY_KEY = 'arn:aws:kms:ca-central-1:666730517561:key/12303b9c-fa89-44a2-8864-fbc7b3903ca9'
SECURITY_ROLE = 'tims-factory-review-security'
IDENTITY = 'deep_security_reviewer_service'


class SecurityAllowanceSigner(_EnrolledSigner):
    key_bindings = {'owner': KEYS['owner']}
    role_bindings = {'owner': ROLES['owner']}
    identities = {'owner': 'tim_brydges'}

    def __init__(self, *, scope, pricing, readiness, **kwargs):
        if type(scope) is not SecurityProviderScope:
            raise StateError('Exact security scope required')
        self.scope, self.pricing, self.readiness = copy.deepcopy((scope, pricing, readiness))
        self.scope.bindings()
        super().__init__(role='owner', **kwargs)

    def _check(self, payload, now):
        validate_unsigned(payload, scope=self.scope, pricing=self.pricing, readiness=self.readiness, now=now)


class SecurityResultSigner(ReviewRoleResultSigner):
    key_bindings = {'security': SECURITY_KEY}
    role_bindings = {'security': SECURITY_ROLE}
    identities = {'security': IDENTITY}

    def __init__(self, *, request, dispatch_id, **kwargs):
        if (type(request) is not DispatchRequest or type(dispatch_id) is not str or
                not re.fullmatch('[a-f0-9]{64}', dispatch_id)):
            raise StateError('Exact security dispatch required')
        self.expected = {'kind':'role_result', 'factory_id':'tims-software-factory',
            'task_id':'bounded-review-004', 'binding':DynamoDBDispatchStore._binding(request),
            'dispatch_id':dispatch_id, 'producer_identity':IDENTITY}
        _EnrolledSigner.__init__(self, role='security', **kwargs)
