"""Disabled deployment composition for one exact bounded provider role.

Deployment authenticates candidate/proof provenance and supplies isolated signing
clients. No event can supply configuration, credentials, keys or a provider route.
"""
import base64
import re
from dataclasses import asdict

from factory_state.model import StateError
from .cloud_roles import ROLE_IDENTITIES, RoleExecutionService
from .review_provider_backend import ReviewProviderBackend
from .review_provider_scope import FACTORY, TASK
from .review_signing import ReviewRoleResultSigner


class BoundedReviewRoleRuntime:
    @staticmethod
    def validate_event(prepared, event):
        expected = {'schema_version': '1.0', 'factory_id': FACTORY, 'task_id': TASK,
                    'worker_id': 'bounded-review-controller',
                    'request': asdict(prepared.scope.request),
                    'input_base64': base64.b64encode(prepared.input_bytes).decode()}
        if (type(event) is not dict or set(event) != set(expected) | {'dispatch_id'} or
                any(type(event[k]) is not type(v) or event[k] != v for k, v in expected.items()) or
                type(event['dispatch_id']) is not str or
                not re.fullmatch('[0-9a-f]{64}', event['dispatch_id'])):
            raise StateError('role event differs from deployment-owned exact job')

    def __init__(self, *, backend, kms, sts, execution_table, enabled=False):
        if (type(backend) is not ReviewProviderBackend or type(enabled) is not bool or
                (enabled and (not backend.enabled or backend.load_credential is None))):
            raise StateError('deployment-owned executable role backend required')
        if execution_table != 'tims-factory-role-executions':
            raise StateError('exact existing role execution table required')
        for client, service in ((kms, 'kms'), (sts, 'sts')):
            if (client.meta.endpoint_url != f'https://{service}.ca-central-1.amazonaws.com' or
                    client.meta.config.retries.get('total_max_attempts') != 1):
                raise StateError('isolated signing clients require regional endpoints and no retries')
        self.backend, self.kms, self.sts = backend, kms, sts
        self.execution_table, self.enabled = execution_table, enabled

    def handle(self, event):
        if not self.enabled:
            raise StateError('bounded role runtime disabled')
        prepared = self.backend.prepared
        self.validate_event(prepared, event)
        state = self.backend.states.load_state(FACTORY, TASK)
        if state is None:
            raise StateError('bounded role task missing')
        now = self.backend.clock()
        self.backend.check_activation(state, prepared.scope.request, now=now)
        self.backend._started(state, prepared.scope.request, event['dispatch_id'], now)
        signer = ReviewRoleResultSigner(role=prepared.scope.role, request=prepared.scope.request,
            dispatch_id=event['dispatch_id'], kms=self.kms, sts=self.sts,
            key_loader=self.backend.key_loader, clock=self.backend.clock, enabled=True)
        signer.preflight()  # No claims, provider credential reads, sends or signatures yet.
        service = RoleExecutionService(self.backend.states, self.backend.ledger,
            execution_table=self.execution_table, deployed_commit=prepared.scope.request.source_commit,
            identity=ROLE_IDENTITIES[prepared.scope.role], key_loader=self.backend.key_loader,
            signer=signer, backend=self.backend, clock=self.backend.clock)
        return service.handle(event)
