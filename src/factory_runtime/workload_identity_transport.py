"""Disabled-by-default JWT exchange with injected trusted subject identity.

No AWS/GitHub identity source, configuration, credential discovery or CLI
activation is provided here. Construction performs no IO.
"""
import asyncio
from dataclasses import dataclass
from datetime import datetime, timezone
import json
import re

from .identity_diagnostics import IdentityFailure, identity_failure
from .credential_issuance import IssuanceAuthorization
from .openai_provider import OpenAIProviderDisabledError, OpenAIProviderProtocolError
from .provider_credentials import ProviderCredentialLeaseError
from .provider_http_transport import DirectOpenAITransport
from .workload_identity_response import ExchangeResponse, RenewableCredentialBinding, _unique


@dataclass(frozen=True, repr=False)
class TrustedSubjectIdentity:
    token: str
    expires_at: datetime


class DirectTokenExchangeTransport(DirectOpenAITransport):
    def __init__(self, *, enabled=False):
        super().__init__(enabled=enabled, max_request_bytes=65536, max_response_bytes=65536)

    async def post_json(self, *, endpoint, headers, body, timeout_seconds):
        if not self.enabled:
            raise OpenAIProviderDisabledError('token exchange disabled')
        try:
            if (endpoint != 'https://auth.openai.com/oauth/token'
                    or type(headers) is not dict
                    or headers != {'Content-Type': 'application/json', 'Accept': 'application/json'}
                    or type(body) is not bytes or not 1 <= len(body) <= self.max_request_bytes
                    or type(timeout_seconds) is not int or not 1 <= timeout_seconds <= 30):
                raise ValueError()
            data = json.loads(body.decode('utf-8'), object_pairs_hook=_unique)
            if (type(data) is not dict or set(data) != {'grant_type', 'subject_token_type',
                    'subject_token', 'identity_provider_id', 'service_account_id'}
                    or data['grant_type'] != 'urn:ietf:params:oauth:grant-type:token-exchange'
                    or data['subject_token_type'] != 'urn:ietf:params:oauth:token-type:jwt'):
                raise ValueError()
            for key in ('identity_provider_id', 'service_account_id'):
                if not isinstance(data[key], str) or not re.fullmatch(r'[A-Za-z0-9_-]{1,128}', data[key]):
                    raise ValueError()
            _validate_subject_token(data['subject_token'])
        except Exception:
            raise OpenAIProviderProtocolError('invalid bounded token exchange request') from None
        return await self._run_request(headers, body, timeout_seconds, kind='token-exchange')


def _validate_subject_token(token):
    if (not isinstance(token, str) or not 16 <= len(token) <= 32768
            or not re.fullmatch(r'[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+', token)):
        raise ValueError('invalid JWT envelope')


class JWTTokenExchange:
    def __init__(self, *, authorization, subject_source, clock, enabled=False, transport=None):
        if (type(authorization) is not IssuanceAuthorization or not callable(subject_source)
                or not callable(clock) or type(enabled) is not bool):
            raise ValueError('trusted exchange configuration required')
        self._authorization = authorization.canonical()
        self._source = subject_source
        self._clock = clock
        self._enabled = enabled
        self._transport = transport if transport is not None else DirectTokenExchangeTransport(enabled=enabled)

    def binding(self, ledger):
        if ledger.authorization.canonical() != self._authorization:
            raise ValueError('exchange authorization differs from ledger')
        return RenewableCredentialBinding(ledger, self)

    async def __call__(self, authorization):
        if not self._enabled:
            raise ProviderCredentialLeaseError('JWT exchange disabled')
        stage = 'exchange_authorization'
        try:
            if type(authorization) is not IssuanceAuthorization or authorization.canonical() != self._authorization:
                raise ValueError()
            started = self._clock()
            if (not isinstance(started, datetime) or started.tzinfo is None or started.utcoffset() is None
                    or not authorization.starts_at <= started < authorization.expires_at):
                raise ValueError()
            async with asyncio.timeout(30):
                stage = 'exchange_subject'
                subject = await self._source(authorization)
                if type(subject) is not TrustedSubjectIdentity:
                    raise ValueError()
                _validate_subject_token(subject.token)
                now = self._clock()
                if (not isinstance(now, datetime) or now.tzinfo is None or now.utcoffset() is None
                        or not isinstance(subject.expires_at, datetime)
                        or subject.expires_at.tzinfo is None or subject.expires_at.utcoffset() is None
                        or now < started
                        or not authorization.starts_at <= now < authorization.expires_at
                        or (subject.expires_at - now).total_seconds() <= 210):
                    raise ValueError()
                body = json.dumps(dict(grant_type='urn:ietf:params:oauth:grant-type:token-exchange',
                    subject_token_type='urn:ietf:params:oauth:token-type:jwt', subject_token=subject.token,
                    identity_provider_id=authorization.identity_provider_id,
                    service_account_id=authorization.service_account_id), separators=(',', ':')).encode()
                stage = 'exchange_transport'
                response = await self._transport.post_json(endpoint='https://auth.openai.com/oauth/token',
                    headers={'Content-Type': 'application/json', 'Accept': 'application/json'},
                    body=body, timeout_seconds=20)
                if response.status_code != 200:
                    raise IdentityFailure('exchange_http', 'http_error')
                return ExchangeResponse(response.body, subject.expires_at.astimezone(timezone.utc))
        except asyncio.CancelledError:
            raise
        except Exception as error:
            raise identity_failure(error, stage) from None
