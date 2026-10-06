"""Disabled, fixed-route one-shot transports. No default credential discovery."""
import hashlib
import http.client
import json
import ssl
import threading
from datetime import datetime, timezone
from urllib.parse import quote

from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest
from botocore.credentials import ReadOnlyCredentials

from factory_state.model import StateError
from factory_state.scope import canonical
from .pilot002_protocols import request_bytes as prepare_request, MAX_RESPONSE_BYTES

REGION='ca-central-1'
PROFILE='global.anthropic.claude-sonnet-4-5-20250929-v1:0'
ROUTES={
    'builder':('api.openai.com','/v1/responses'),
    'inspector':('bedrock-runtime.ca-central-1.amazonaws.com','/model/'+quote(PROFILE,safe='')+'/converse'),
    'qa':('generativelanguage.googleapis.com','/v1beta/models/gemini-3.8-flash:generateContent'),
}


class ProviderHTTPStatusError(StateError):
    """Numeric error status only; never retain provider text, headers or body."""
    def __init__(self, status):
        self.http_status = status if type(status) is int and 300 <= status <= 599 else None
        super().__init__('Pilot 002 provider transport failed; reconcile without retry')


class ProviderTimeoutError(StateError):
    """A timeout category without exception text, headers, or credentials."""
    def __init__(self):
        super().__init__('Pilot 002 provider transport failed; reconcile without retry')


class _QuietSigV4(SigV4Auth):
    def add_auth(self, request):
        # The SDK's ordinary add_auth logs the canonical request (including the
        # session token) at DEBUG. Reuse its signing primitives without logging.
        request.context['timestamp']=datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
        self._modify_request_before_signing(request)
        signature=self.signature(self.string_to_sign(request,self.canonical_request(request)),request)
        self._inject_signature_to_request(request,signature)


def _secret(value, minimum=16, maximum=512):
    if (not isinstance(value,str) or not minimum<=len(value)<=maximum or
            any(ord(c)<33 or ord(c)>126 for c in value)):
        raise ValueError('invalid credential')
    return value


class Pilot002Transport:
    """Use only after a durable claim and fresh signed allowance verification.

enabled, repository root, role and candidate context are deployment-owned.
The latch survives errors on this instance only, not process restarts. The
workflow's permanent role claim remains mandatory for cross-instance safety.
"""
    prepare = staticmethod(prepare_request)
    routes = ROUTES

    def __init__(self, root, *, role, builder_response=None, candidate_commit=None, enabled=False):
        self._expected=self.prepare(root,role=role,builder_response=builder_response,candidate_commit=candidate_commit)
        self._role=role
        self._host,self._path=self.routes[role]
        self._enabled=enabled is True
        self._attempted=False
        self._lock=threading.Lock()

    def send_once(self, *, request_bytes, credential, expected_request_digest):
        if not self._enabled:raise StateError('Pilot 002 transport disabled')
        if (type(request_bytes) is not bytes or request_bytes!=self._expected or
                expected_request_digest!='sha256:'+hashlib.sha256(self._expected).hexdigest()):
            raise StateError('Pilot 002 transport request differs from prepared allowance bytes')
        with self._lock:
            if self._attempted:raise StateError('Pilot 002 transport already attempted; reconcile without retry')
            self._attempted=True
        connection=None
        try:
            body=request_bytes
            headers={'Host':self._host,'Content-Type':'application/json','Accept':'application/json',
                'Accept-Encoding':'identity','Connection':'close'}
            if self._role=='builder':headers['Authorization']='Bearer '+_secret(credential)
            elif self._role=='qa':headers['x-goog-api-key']=_secret(credential)
            else:
                if not isinstance(credential,ReadOnlyCredentials):raise ValueError('frozen AWS credentials required')
                _secret(credential.access_key,16,128);_secret(credential.secret_key,16,256)
                _secret(credential.token,16,8192)
                args=json.loads(request_bytes)
                if args.pop('modelId')!=PROFILE:raise ValueError('profile differs')
                body=canonical(args)
                request=AWSRequest(method='POST',url='https://'+self._host+self._path,data=body,headers=headers)
                _QuietSigV4(credential,'bedrock',REGION).add_auth(request)
                headers=dict(request.headers)
            context=ssl.create_default_context()
            context.set_alpn_protocols(['http/1.1'])
            connection=http.client.HTTPSConnection(self._host,443,timeout=90,context=context)
            connection.set_debuglevel(0)
            # No proxy discovery, redirects, SDK invocation or retry loop.
            connection.request('POST',self._path,body=body,headers=headers)
            response=connection.getresponse()
            if response.status!=200:
                raise ProviderHTTPStatusError(response.status)
            if (response.getheader('Content-Type','').split(';',1)[0].strip().lower()!='application/json' or
                    response.getheader('Content-Encoding','identity').lower()!='identity'):
                raise ValueError('provider status or content type differs')
            raw=response.read(MAX_RESPONSE_BYTES+1)
            if not isinstance(raw,bytes) or not 0<len(raw)<=MAX_RESPONSE_BYTES:
                raise ValueError('provider response exceeds bound')
            return raw
        except ProviderHTTPStatusError:
            raise
        except TimeoutError:
            raise ProviderTimeoutError() from None
        except Exception:
            raise StateError('Pilot 002 provider transport failed; reconcile without retry') from None
        finally:
            credential=None
            if connection is not None:
                try:connection.close()
                except Exception:pass
