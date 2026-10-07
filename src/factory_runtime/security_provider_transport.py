"""Fixed regional Bedrock route; only TLS/SigV4 mechanics are shared."""
from factory_state.model import StateError
from .pilot002_transport import Pilot002Transport, ROUTES
from .security_provider_protocol import PreparedSecurityRequest


class SecurityProviderTransport(Pilot002Transport):
    routes = {'security': ROUTES['inspector']}

    @staticmethod
    def prepare(prepared, *, role, builder_response=None, candidate_commit=None):
        if (type(prepared) is not PreparedSecurityRequest or role != 'security' or
                builder_response is not None or candidate_commit is not None):
            raise StateError('Exact security transport preparation required')
        prepared.validate()
        return prepared.scope.request_bytes

    def __init__(self, prepared, *, enabled=False):
        if type(enabled) is not bool:
            raise StateError('Explicit security transport configuration required')
        super().__init__(prepared, role='security', enabled=enabled)
