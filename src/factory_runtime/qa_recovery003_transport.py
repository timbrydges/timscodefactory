"""Fixed Gemini 3.7 route using the reviewed single-send transport implementation."""
import threading
from factory_state.model import StateError
from .pilot002_transport import Pilot002Transport as OriginalTransport
from .qa_recovery003_protocols import request_bytes


class Pilot002Transport(OriginalTransport):
    def __init__(self,root,*,role,builder_response=None,candidate_commit=None,enabled=False):
        if role!='qa':raise StateError('Recovery 003 transport is QA only')
        self._expected=request_bytes(root,role=role,builder_response=builder_response,candidate_commit=candidate_commit)
        self._role='qa'
        self._timeout=90
        self._host='generativelanguage.googleapis.com'
        self._path='/v1beta/models/gemini-3.7-flash:generateContent'
        self._enabled=enabled is True
        self._attempted=False
        self._lock=threading.Lock()
