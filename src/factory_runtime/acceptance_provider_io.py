"""Pinned pricing and one-shot HTTPS I/O for the isolated acceptance broker.

The checked-in quote is intentionally expired. Refreshing its paired evidence
and clearing the activation gates are separate owner-reviewed operations.
"""
from __future__ import annotations

import asyncio
import ssl
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from factory_state.model import StateError

from .autonomy_contract import load_autonomy_operating_allowance
from .openai_provider import (
    OpenAIProviderPricingError, OpenAIProviderProtocolError,
    ProviderHTTPResponse, ProviderPricingQuote,
)
from .provider_broker_service import ResolvedProviderTarget


@dataclass(frozen=True)
class AcceptanceContractPricingSource:
    repository_root: Path

    async def quote(self, *, target: ResolvedProviderTarget) -> ProviderPricingQuote:
        if (not isinstance(target, ResolvedProviderTarget) or
                target.provider_family != 'openai' or target.model_id != 'gpt-5.6-sol'):
            raise OpenAIProviderPricingError('acceptance pricing target differs')
        try:
            allowance = load_autonomy_operating_allowance(Path(self.repository_root))
        except (StateError, TypeError, ValueError) as exc:
            raise OpenAIProviderPricingError('acceptance pricing contract is invalid') from exc
        now = datetime.now(timezone.utc)
        if (allowance.provider_family != target.provider_family or
                allowance.model_id != target.model_id or
                not allowance.pricing_observed_at <= now < allowance.pricing_expires_at):
            raise OpenAIProviderPricingError('acceptance pricing has expired or differs')
        return ProviderPricingQuote(
            model_id=target.model_id,
            input_usd_per_million_tokens=allowance.pricing_input_usd_per_million_tokens,
            output_usd_per_million_tokens=allowance.pricing_output_usd_per_million_tokens,
            effective_at=allowance.pricing_observed_at,
            expires_at=allowance.pricing_expires_at,
            source_id=allowance.contract_id,
        )


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        raise OpenAIProviderProtocolError('acceptance provider redirect is prohibited')


class AcceptanceOpenAIHTTPTransport:
    """No proxy, no redirect, no retry, exact HTTPS endpoint, bounded response."""

    _ENDPOINT = 'https://api.openai.com/v1/responses'
    _MAX_RESPONSE_BYTES = 256 * 1024

    def __init__(self, *, opener=None):
        self._opener = opener or urllib.request.build_opener(
            urllib.request.ProxyHandler({}),
            urllib.request.HTTPSHandler(context=ssl.create_default_context()),
            _NoRedirect(),
        )

    async def post_json(self, *, endpoint: str, headers: dict[str, str],
                        body: bytes, timeout_seconds: int) -> ProviderHTTPResponse:
        if (endpoint != self._ENDPOINT or not isinstance(body, bytes) or
                len(body) > 42020 or
                type(timeout_seconds) is not int or not 1 <= timeout_seconds <= 180 or
                not isinstance(headers, dict) or set(headers) !=
                {'Authorization', 'Content-Type', 'Accept'} or
                headers.get('Content-Type') != 'application/json' or
                headers.get('Accept') != 'application/json' or
                not isinstance(headers.get('Authorization'), str) or
                not headers['Authorization'].startswith('Bearer ')):
            raise OpenAIProviderProtocolError('acceptance HTTP request is invalid')
        request = urllib.request.Request(endpoint, data=body, headers=headers, method='POST')

        def send_once():
            try:
                with self._opener.open(request, timeout=timeout_seconds) as response:
                    payload = response.read(self._MAX_RESPONSE_BYTES + 1)
                    if len(payload) > self._MAX_RESPONSE_BYTES:
                        raise OpenAIProviderProtocolError('acceptance HTTP response exceeds byte cap')
                    return ProviderHTTPResponse(response.status, payload)
            except urllib.error.HTTPError as exc:
                # Error bodies can contain sensitive upstream data; discard them.
                return ProviderHTTPResponse(exc.code, b'')
            except (urllib.error.URLError, TimeoutError, OSError) as exc:
                raise OpenAIProviderProtocolError('acceptance provider connection failed') from exc

        return await asyncio.to_thread(send_once)
