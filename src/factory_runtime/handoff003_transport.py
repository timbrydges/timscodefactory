"""Fixed fresh-task routes using the reviewed no-retry HTTPS transport."""
from .handoff003_protocols import request_bytes
from .pilot002_transport import Pilot002Transport, ROUTES


class Handoff003Transport(Pilot002Transport):
    prepare = staticmethod(request_bytes)
    routes = {**ROUTES, 'qa': ('generativelanguage.googleapis.com',
        '/v1beta/models/gemini-3.7-flash:generateContent')}
