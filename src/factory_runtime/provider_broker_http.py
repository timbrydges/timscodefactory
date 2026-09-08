"""Reference HTTP/auth edge for the internal provider broker.

Raw Bearer credentials terminate here. The authenticator validates the token and
returns only a short-lived BrokerAuthContext; the provider-broker service core
never receives or stores the token. This module intentionally models an HTTP
application boundary without opening a socket or configuring TLS. A future
internal ingress/runtime must provide TLS and route only the approved broker
hostname/path to this application.
"""

from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass
from typing import Protocol

from .provider_broker import BrokerHTTPResponse
from .provider_broker_service import (
    BrokerAuthContext,
    ProviderBrokerAuthenticationError,
    ProviderBrokerIdempotencyConflict,
    ProviderBrokerInvocationError,
    ProviderBrokerRequestError,
    ProviderBrokerServiceError,
    ReferenceProviderBrokerService,
)


_APPROVED_PATH = "/v1/repair/decide"
_JSON_CONTENT_TYPE = "application/json"


class ProviderBrokerHTTPEdgeError(RuntimeError):
    """Base class for HTTP-edge configuration failures."""


class BrokerTokenRejected(ProviderBrokerHTTPEdgeError):
    """Authenticator determined that the presented Bearer token is invalid."""


class BrokerAuthenticatorUnavailable(ProviderBrokerHTTPEdgeError):
    """Authenticator could not validate the token due to infrastructure failure."""


class BearerTokenAuthenticator(Protocol):
    async def authenticate(self, token: str) -> BrokerAuthContext:
        """Validate one raw token and return only its bound identity context."""
        ...


@dataclass(frozen=True)
class BrokerHTTPRequest:
    """Minimal duplicate-preserving HTTP request model."""

    method: str
    path: str
    headers: tuple[tuple[str, str], ...]
    body: bytes


@dataclass(frozen=True)
class BrokerHTTPApplicationResponse:
    status_code: int
    headers: tuple[tuple[str, str], ...]
    body: bytes


@dataclass(frozen=True)
class BrokerHTTPEdgePolicy:
    max_body_bytes: int = 256 * 1024
    max_header_count: int = 32
    max_header_name_chars: int = 128
    max_header_value_chars: int = 8192
    max_bearer_token_chars: int = 4096
    auth_timeout_seconds: int = 10

    def __post_init__(self) -> None:
        for name, value, low, high in (
            ("max_body_bytes", self.max_body_bytes, 1024, 1024 * 1024),
            ("max_header_count", self.max_header_count, 1, 128),
            ("max_header_name_chars", self.max_header_name_chars, 1, 512),
            ("max_header_value_chars", self.max_header_value_chars, 1, 32768),
            ("max_bearer_token_chars", self.max_bearer_token_chars, 16, 16384),
            ("auth_timeout_seconds", self.auth_timeout_seconds, 1, 60),
        ):
            if isinstance(value, bool) or not isinstance(value, int) or value < low or value > high:
                raise ValueError(f"{name} must be between {low} and {high}")


def _json_error(status: int, code: str) -> BrokerHTTPApplicationResponse:
    body = json.dumps(
        {"error": {"code": code}},
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return BrokerHTTPApplicationResponse(
        status_code=status,
        headers=(
            ("Content-Type", _JSON_CONTENT_TYPE),
            ("Cache-Control", "no-store"),
            ("X-Content-Type-Options", "nosniff"),
        ),
        body=body,
    )


def _success(response: BrokerHTTPResponse) -> BrokerHTTPApplicationResponse:
    return BrokerHTTPApplicationResponse(
        status_code=response.status_code,
        headers=(
            ("Content-Type", _JSON_CONTENT_TYPE),
            ("Cache-Control", "no-store"),
            ("X-Content-Type-Options", "nosniff"),
        ),
        body=response.body,
    )


def _validate_header_pair(name: str, value: str, policy: BrokerHTTPEdgePolicy) -> None:
    if not isinstance(name, str) or not isinstance(value, str):
        raise ProviderBrokerHTTPEdgeError("HTTP headers must be strings")
    if not name or len(name) > policy.max_header_name_chars:
        raise ProviderBrokerHTTPEdgeError("HTTP header name is invalid")
    if len(value) > policy.max_header_value_chars:
        raise ProviderBrokerHTTPEdgeError("HTTP header value is too long")
    if any(ch in name for ch in "\r\n:\t ") or any(ch in value for ch in "\r\n"):
        raise ProviderBrokerHTTPEdgeError("HTTP header contains prohibited characters")


def _header_values(request: BrokerHTTPRequest, name: str) -> tuple[str, ...]:
    lowered = name.lower()
    return tuple(value for key, value in request.headers if key.lower() == lowered)


def _single_header(request: BrokerHTTPRequest, name: str, *, required: bool = True) -> str | None:
    values = _header_values(request, name)
    if not values:
        if required:
            raise ProviderBrokerHTTPEdgeError(f"missing required header: {name}")
        return None
    if len(values) != 1:
        raise ProviderBrokerHTTPEdgeError(f"duplicate header is prohibited: {name}")
    return values[0].strip()


def _bearer_token(request: BrokerHTTPRequest, policy: BrokerHTTPEdgePolicy) -> str:
    value = _single_header(request, "Authorization")
    assert value is not None
    parts = value.split(" ", 1)
    if len(parts) != 2 or parts[0].lower() != "bearer":
        raise BrokerTokenRejected("authorization scheme is not Bearer")
    token = parts[1]
    if len(token) < 16 or len(token) > policy.max_bearer_token_chars:
        raise BrokerTokenRejected("bearer token length is invalid")
    if any(ord(ch) < 33 or ord(ch) > 126 for ch in token):
        raise BrokerTokenRejected("bearer token contains invalid characters")
    return token


class ReferenceProviderBrokerHTTPApplication:
    """Fail-closed HTTP adapter around ReferenceProviderBrokerService."""

    def __init__(
        self,
        service: ReferenceProviderBrokerService,
        authenticator: BearerTokenAuthenticator,
        *,
        policy: BrokerHTTPEdgePolicy | None = None,
    ) -> None:
        self.service = service
        self.authenticator = authenticator
        self.policy = policy or BrokerHTTPEdgePolicy()

    async def handle(self, request: BrokerHTTPRequest) -> BrokerHTTPApplicationResponse:
        if not isinstance(request, BrokerHTTPRequest):
            return _json_error(400, "invalid_request")
        if request.method != "POST":
            return _json_error(405, "method_not_allowed")
        if request.path != _APPROVED_PATH:
            return _json_error(404, "not_found")
        if not isinstance(request.body, bytes):
            return _json_error(400, "invalid_request")
        if len(request.body) > self.policy.max_body_bytes:
            return _json_error(413, "request_too_large")
        if len(request.headers) > self.policy.max_header_count:
            return _json_error(431, "too_many_headers")

        try:
            for name, value in request.headers:
                _validate_header_pair(name, value, self.policy)
            content_type = _single_header(request, "Content-Type")
            if content_type != _JSON_CONTENT_TYPE:
                return _json_error(415, "unsupported_media_type")
            accept = _single_header(request, "Accept", required=False)
            if accept is not None and accept not in {_JSON_CONTENT_TYPE, "*/*"}:
                return _json_error(406, "not_acceptable")
            token = _bearer_token(request, self.policy)
        except BrokerTokenRejected:
            return _json_error(401, "unauthorized")
        except ProviderBrokerHTTPEdgeError:
            return _json_error(400, "invalid_request")

        try:
            auth = await asyncio.wait_for(
                self.authenticator.authenticate(token),
                timeout=self.policy.auth_timeout_seconds,
            )
        except BrokerTokenRejected:
            return _json_error(401, "unauthorized")
        except (BrokerAuthenticatorUnavailable, asyncio.TimeoutError):
            return _json_error(503, "auth_unavailable")
        except Exception:
            return _json_error(503, "auth_unavailable")
        finally:
            # The local name is cleared before entering the broker service core;
            # no raw credential is passed across the service boundary.
            token = ""

        try:
            response = await self.service.handle(body=request.body, auth=auth)
        except ProviderBrokerAuthenticationError:
            return _json_error(401, "unauthorized")
        except ProviderBrokerRequestError:
            return _json_error(400, "invalid_request")
        except ProviderBrokerIdempotencyConflict:
            return _json_error(409, "idempotency_conflict")
        except ProviderBrokerInvocationError:
            return _json_error(502, "provider_failure")
        except ProviderBrokerServiceError:
            return _json_error(500, "broker_internal_error")
        except Exception:
            return _json_error(500, "broker_internal_error")

        if response.status_code != 200:
            return _json_error(500, "broker_internal_error")
        return _success(response)
