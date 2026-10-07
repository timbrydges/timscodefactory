"""Disabled exact security role composition; no Lambda entrypoint or deployment."""
import base64
from dataclasses import asdict
import re
from factory_state.model import StateError
from .cloud_roles import RoleExecutionService
from .security_provider_backend import SecurityProviderBackend
from .security_signing import SecurityResultSigner, IDENTITY


class BoundedSecurityRoleRuntime:
    @staticmethod
    def validate_event(prepared, event):
        expected = {'schema_version':'1.0', 'factory_id':'tims-software-factory',
            'task_id':'bounded-review-004', 'worker_id':'bounded-security-controller',
            'request':asdict(prepared.scope.request),
            'input_base64':base64.b64encode(prepared.input_bytes).decode()}
        if (type(event) is not dict or set(event) != set(expected) | {'dispatch_id'} or
                any(type(event[k]) is not type(v) or event[k] != v for k,v in expected.items()) or
                type(event['dispatch_id']) is not str or not re.fullmatch('[a-f0-9]{64}',event['dispatch_id'])):
            raise StateError('Security event differs from exact deployment job')

    def __init__(self, *, backend, kms, sts, execution_table, enabled=False):
        if (type(backend) is not SecurityProviderBackend or type(enabled) is not bool or
                (enabled and (not backend.enabled or backend.load_credential is None)) or
                execution_table != 'tims-factory-role-executions'):
            raise StateError('Exact executable security backend and table required')
        for client, service in ((kms,'kms'),(sts,'sts')):
            if (client.meta.endpoint_url != f'https://{service}.ca-central-1.amazonaws.com' or
                    client.meta.config.retries.get('total_max_attempts') != 1):
                raise StateError('Security signing requires regional no-retry clients')
        self.backend, self.kms, self.sts = backend, kms, sts
        self.execution_table, self.enabled = execution_table, enabled

    def handle(self, event):
        if not self.enabled:
            raise StateError('Security role runtime disabled')
        prepared = self.backend.prepared
        self.validate_event(prepared,event)
        q = prepared.scope.binding.qa
        state = self.backend.states.load_state(q.factory_id,q.task_id)
        if state is None:
            raise StateError('Security task missing')
        now = self.backend.clock()
        self.backend.check_activation(state,prepared.scope.request,now=now)
        self.backend._started(state,prepared.scope.request,event['dispatch_id'],now)
        signer = SecurityResultSigner(request=prepared.scope.request,dispatch_id=event['dispatch_id'],
            kms=self.kms,sts=self.sts,key_loader=self.backend.key_loader,clock=self.backend.clock,enabled=True)
        signer.preflight()
        return RoleExecutionService(self.backend.states,self.backend.ledger,
            execution_table=self.execution_table,deployed_commit=prepared.scope.request.source_commit,
            identity=IDENTITY,key_loader=self.backend.key_loader,signer=signer,backend=self.backend,
            clock=self.backend.clock).handle(event)
