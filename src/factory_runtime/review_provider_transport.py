"""Fixed three-provider routes; reuse TLS/SigV4 mechanics, never old allowances."""
from factory_state.model import StateError
from .pilot002_transport import Pilot002Transport, ROUTES
from .review_provider_protocol import PreparedProviderRequest


class ReviewProviderTransport(Pilot002Transport):
    routes = {**ROUTES, 'qa': ('generativelanguage.googleapis.com',
                             '/v1beta/models/gemini-3.7-flash:generateContent')}

    @staticmethod
    def prepare(prepared, *, role, builder_response=None, candidate_commit=None):
        if (type(prepared) is not PreparedProviderRequest or prepared.scope.role != role or
                builder_response is not None or candidate_commit is not None):
            raise StateError('exact fresh transport preparation required')
        prepared.validate()
        return prepared.scope.request_bytes

    def __init__(self, prepared, *, enabled=False):
        if type(prepared) is not PreparedProviderRequest or type(enabled) is not bool:
            raise StateError('explicit fresh provider transport configuration required')
        super().__init__(prepared, role=prepared.scope.role, enabled=enabled)
