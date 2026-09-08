"""Reference provider-broker service contract for dry-run validation.

This service is intentionally provider-neutral and non-authoritative. It accepts
only the strict repair-broker v1 protocol, independently verifies deterministic
request binding, authenticates an already-validated ephemeral caller context,
resolves the symbolic Factory model selector server-side, invokes a provider
through an injected credential-owning adapter, enforces caller and broker spend
limits, validates the structured decision, and returns a normalized response.

No vendor credential crosses this interface. No GitHub, Factory-state, release,
or shell capability exists here. This module is a reference service core, not a
network listener and not a live provider integration.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any, Protocol

from jsonschema import Draft202012Validator

from .provider_broker import BrokerHTTPResponse, ProviderBrokerBinding


_PROTOCOL_VERSION = "factory-repair-broker-v1"
_EXPECTED_TASK = "structured_ci_repair_decision"
_EXPECTED_DECISION_SCHEMA = "1"
_EXPECTED_AUDIENCE = "provider-broker.internal"
_REQUEST_SCHEMA_PATH = "factory/schemas/provider-broker-repair-request.schema.json"
_RESPONSE_SCHEMA_PATH = "factory/schemas/provider-broker-repair-response.schema.json"


class ProviderBrokerServiceError(RuntimeError):
    """Base class for reference broker service failures."""


class ProviderBrokerAuthenticationError(ProviderBrokerServiceError):
    """Caller authentication context is invalid for the broker service."""


class ProviderBrokerRequestError(ProviderBrokerServiceError):
    """Request body is malformed, unbound, or violates broker policy."""


class ProviderBrokerInvocationError(ProviderBrokerServiceError):
    """Provider resolution/invocation result cannot be trusted."""


class ProviderBrokerIdempotencyConflict(ProviderBrokerServiceError):
    """An idempotency key was reused with different request bytes."""


def _canonical_json(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def _sha256(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _parse_positive_decimal(value: Any, field: str) -> Decimal:
    if not isinstance(value, str):
        raise ProviderBrokerRequestError(f"{field} must be a decimal string")
    try:
        parsed = Decimal(value)
    except InvalidOperation as exc:
        raise ProviderBrokerRequestError(f"{field} is invalid") from exc
    if not parsed.is_finite() or parsed <= 0:
        raise ProviderBrokerRequestError(f"{field} must be positive and finite")
    return parsed


def _parse_nonnegative_decimal(value: Any, field: str) -> Decimal:
    if not isinstance(value, Decimal) or not value.is_finite() or value < 0:
        raise ProviderBrokerInvocationError(f"{field} must be a finite nonnegative Decimal")
    return value


def _read_schema(root: Path, relative: str) -> Draft202012Validator:
    path = root / relative
    try:
        parsed = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ProviderBrokerRequestError(f"cannot load broker schema: {relative}") from exc
    Draft202012Validator.check_schema(parsed)
    return Draft202012Validator(parsed)


def _validate_with_schema(
    validator: Draft202012Validator,
    value: Any,
    *,
    context: str,
) -> None:
    errors = sorted(validator.iter_errors(value), key=lambda item: list(item.absolute_path))
    if errors:
        first = errors[0]
        location = ".".join(str(part) for part in first.absolute_path) or "<root>"
        raise ProviderBrokerRequestError(f"{context} schema violation at {location}: {first.message}")


def _request_seed(payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "protocol_version": payload["protocol_version"],
        "binding_digest": payload["binding_digest"],
        "role_id": payload["role_id"],
        "provider_profile": payload["provider_profile"],
        "provider_family": payload["provider_family"],
        "model_selector": payload["model_selector"],
        "task": payload["task"],
        "decision_schema_version": payload["decision_schema_version"],
        "turn": payload["turn"],
    }


@dataclass(frozen=True)
class BrokerAuthContext:
    """Authentication result supplied by the future HTTPS/auth boundary.

    Raw bearer tokens are deliberately absent. The network/auth layer must
    validate the token and pass only this short-lived identity context inward.
    """

    subject: str
    audience: str
    issued_at: datetime
    expires_at: datetime


@dataclass(frozen=True)
class BrokerServicePolicy:
    """Server-owned limits that the client cannot raise."""

    allowed_subjects: tuple[str, ...] = ("engineering_agent_service",)
    max_request_bytes: int = 256 * 1024
    max_response_bytes: int = 64 * 1024
    max_cost_usd_per_request: Decimal = Decimal("1.00")
    max_auth_ttl_seconds: int = 900
    provider_timeout_seconds: int = 90

    def __post_init__(self) -> None:
        if not self.allowed_subjects or any(
            not isinstance(item, str) or not item or any(ch.isspace() for ch in item)
            for item in self.allowed_subjects
        ):
            raise ValueError("allowed_subjects must contain valid nonempty identities")
        if len(set(self.allowed_subjects)) != len(self.allowed_subjects):
            raise ValueError("allowed_subjects contains duplicates")
        for name, value, low, high in (
            ("max_request_bytes", self.max_request_bytes, 1024, 1024 * 1024),
            ("max_response_bytes", self.max_response_bytes, 1024, 1024 * 1024),
            ("max_auth_ttl_seconds", self.max_auth_ttl_seconds, 30, 3600),
            ("provider_timeout_seconds", self.provider_timeout_seconds, 1, 300),
        ):
            if isinstance(value, bool) or not isinstance(value, int) or value < low or value > high:
                raise ValueError(f"{name} must be between {low} and {high}")
        if (
            not isinstance(self.max_cost_usd_per_request, Decimal)
            or not self.max_cost_usd_per_request.is_finite()
            or self.max_cost_usd_per_request <= 0
        ):
            raise ValueError("max_cost_usd_per_request must be a positive finite Decimal")


@dataclass(frozen=True)
class ResolvedProviderTarget:
    """Server-side resolution of a symbolic Factory model selector."""

    provider_family: str
    model_id: str
    selector_version: str

    def __post_init__(self) -> None:
        for name in ("provider_family", "model_id", "selector_version"):
            value = getattr(self, name)
            if not isinstance(value, str) or not value or any(ord(ch) < 32 for ch in value):
                raise ProviderBrokerInvocationError(f"resolved provider {name} is invalid")


class ProviderSelectorResolver(Protocol):
    def resolve(
        self,
        *,
        provider_profile: str,
        provider_family: str,
        model_selector: str,
    ) -> ResolvedProviderTarget:
        ...


@dataclass(frozen=True)
class ProviderInvocationResult:
    """Credential-owning provider adapter's normalized result.

    There is intentionally no raw provider response or provider credential field.
    """

    decision: dict[str, Any]
    input_tokens: int
    output_tokens: int
    cost_usd: Decimal

    def __post_init__(self) -> None:
        if not isinstance(self.decision, dict):
            raise ProviderBrokerInvocationError("provider decision must be an object")
        for name in ("input_tokens", "output_tokens"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise ProviderBrokerInvocationError(f"{name} must be a nonnegative integer")
        _parse_nonnegative_decimal(self.cost_usd, "cost_usd")


class ProviderInvoker(Protocol):
    async def invoke(
        self,
        *,
        target: ResolvedProviderTarget,
        turn: dict[str, Any],
        max_cost_usd: Decimal,
        decision_schema_version: str,
    ) -> ProviderInvocationResult:
        """Invoke a provider using credentials held entirely behind this interface."""
        ...


@dataclass(frozen=True)
class IdempotencyRecord:
    request_digest: str
    response: bytes


class IdempotencyStore(Protocol):
    def get(self, key: str) -> IdempotencyRecord | None:
        ...

    def put_if_absent(self, key: str, record: IdempotencyRecord) -> IdempotencyRecord:
        """Insert or return the existing record atomically."""
        ...


class InMemoryBrokerIdempotencyStore:
    """Reference deterministic store for unit tests and single-process dry runs."""

    def __init__(self) -> None:
        self._records: dict[str, IdempotencyRecord] = {}

    def get(self, key: str) -> IdempotencyRecord | None:
        return self._records.get(key)

    def put_if_absent(self, key: str, record: IdempotencyRecord) -> IdempotencyRecord:
        existing = self._records.get(key)
        if existing is not None:
            return existing
        self._records[key] = record
        return record


class StaticProviderSelectorResolver:
    """Explicit selector table useful for dry-run conformance tests."""

    def __init__(self, mappings: tuple[tuple[str, str, str, str, str], ...]) -> None:
        # (profile, family, selector, model_id, selector_version)
        self._mappings: dict[tuple[str, str, str], ResolvedProviderTarget] = {}
        for profile, family, selector, model_id, selector_version in mappings:
            key = (profile, family, selector)
            if key in self._mappings:
                raise ValueError("duplicate provider selector mapping")
            self._mappings[key] = ResolvedProviderTarget(
                provider_family=family,
                model_id=model_id,
                selector_version=selector_version,
            )

    def resolve(
        self,
        *,
        provider_profile: str,
        provider_family: str,
        model_selector: str,
    ) -> ResolvedProviderTarget:
        target = self._mappings.get((provider_profile, provider_family, model_selector))
        if target is None:
            raise ProviderBrokerInvocationError("provider model selector cannot be resolved")
        return target


class ReferenceProviderBrokerService:
    """Strict service core for the provider-broker repair protocol."""

    def __init__(
        self,
        factory_repository_root: Path,
        binding: ProviderBrokerBinding,
        selector_resolver: ProviderSelectorResolver,
        provider_invoker: ProviderInvoker,
        *,
        idempotency_store: IdempotencyStore | None = None,
        policy: BrokerServicePolicy | None = None,
    ) -> None:
        self.factory_repository_root = factory_repository_root.resolve()
        self.binding = binding
        self.selector_resolver = selector_resolver
        self.provider_invoker = provider_invoker
        self.idempotency_store = idempotency_store or InMemoryBrokerIdempotencyStore()
        self.policy = policy or BrokerServicePolicy()
        self._request_validator = _read_schema(self.factory_repository_root, _REQUEST_SCHEMA_PATH)
        self._response_validator = _read_schema(self.factory_repository_root, _RESPONSE_SCHEMA_PATH)

    def _validate_auth(self, auth: BrokerAuthContext, *, now: datetime) -> None:
        if not isinstance(auth, BrokerAuthContext):
            raise ProviderBrokerAuthenticationError("broker auth context is required")
        if auth.subject not in self.policy.allowed_subjects:
            raise ProviderBrokerAuthenticationError("broker caller subject is not allowed")
        if auth.audience != _EXPECTED_AUDIENCE:
            raise ProviderBrokerAuthenticationError("broker caller audience is invalid")
        if not isinstance(auth.issued_at, datetime) or not isinstance(auth.expires_at, datetime):
            raise ProviderBrokerAuthenticationError("broker auth timestamps must be datetimes")
        if (
            auth.issued_at.tzinfo is None
            or auth.issued_at.utcoffset() is None
            or auth.expires_at.tzinfo is None
            or auth.expires_at.utcoffset() is None
        ):
            raise ProviderBrokerAuthenticationError("broker auth timestamps must be timezone-aware")
        if auth.issued_at > now + timedelta(seconds=30):
            raise ProviderBrokerAuthenticationError("broker auth context is future-issued")
        if auth.expires_at <= now:
            raise ProviderBrokerAuthenticationError("broker auth context is expired")
        ttl = (auth.expires_at - auth.issued_at).total_seconds()
        if ttl <= 0 or ttl > self.policy.max_auth_ttl_seconds:
            raise ProviderBrokerAuthenticationError("broker auth context exceeds TTL policy")

    def _parse_request(self, body: bytes) -> tuple[dict[str, Any], str, Decimal]:
        if not isinstance(body, bytes):
            raise ProviderBrokerRequestError("broker request body must be bytes")
        if len(body) > self.policy.max_request_bytes:
            raise ProviderBrokerRequestError("broker request exceeds server byte cap")
        try:
            payload = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ProviderBrokerRequestError("broker request is not valid UTF-8 JSON") from exc
        if not isinstance(payload, dict):
            raise ProviderBrokerRequestError("broker request must be an object")
        _validate_with_schema(self._request_validator, payload, context="broker request")

        expected_pairs = {
            "protocol_version": _PROTOCOL_VERSION,
            "binding_digest": self.binding.binding_digest,
            "role_id": self.binding.role_id,
            "provider_profile": self.binding.provider_profile,
            "provider_family": self.binding.provider_family,
            "model_selector": self.binding.model_selector,
            "task": _EXPECTED_TASK,
            "decision_schema_version": _EXPECTED_DECISION_SCHEMA,
        }
        for field, expected in expected_pairs.items():
            if payload[field] != expected:
                raise ProviderBrokerRequestError(f"broker request {field} does not match service binding")

        expected_request_id = _sha256(_canonical_json(_request_seed(payload)))
        if payload["request_id"] != expected_request_id:
            raise ProviderBrokerRequestError("broker request_id does not match canonical request seed")
        if payload["idempotency_key"] != expected_request_id:
            raise ProviderBrokerRequestError("broker idempotency_key must equal canonical request_id")

        granted_cost = _parse_positive_decimal(payload["budget"]["max_cost_usd"], "max_cost_usd")
        if granted_cost > self.policy.max_cost_usd_per_request:
            raise ProviderBrokerRequestError("caller cost grant exceeds broker service ceiling")
        return payload, expected_request_id, granted_cost

    async def handle(
        self,
        *,
        body: bytes,
        auth: BrokerAuthContext,
        now: datetime | None = None,
    ) -> BrokerHTTPResponse:
        now = now or datetime.now(timezone.utc)
        if now.tzinfo is None or now.utcoffset() is None:
            raise ProviderBrokerAuthenticationError("broker service time must be timezone-aware")
        self._validate_auth(auth, now=now)
        payload, request_id, granted_cost = self._parse_request(body)

        request_digest = _sha256(body)
        existing = self.idempotency_store.get(request_id)
        if existing is not None:
            if existing.request_digest != request_digest:
                raise ProviderBrokerIdempotencyConflict(
                    "idempotency key was reused with different request bytes"
                )
            return BrokerHTTPResponse(status_code=200, body=existing.response)

        target = self.selector_resolver.resolve(
            provider_profile=payload["provider_profile"],
            provider_family=payload["provider_family"],
            model_selector=payload["model_selector"],
        )
        if target.provider_family != self.binding.provider_family:
            raise ProviderBrokerInvocationError("resolved provider family does not match Factory binding")

        try:
            result = await asyncio.wait_for(
                self.provider_invoker.invoke(
                    target=target,
                    turn=payload["turn"],
                    max_cost_usd=granted_cost,
                    decision_schema_version=payload["decision_schema_version"],
                ),
                timeout=self.policy.provider_timeout_seconds,
            )
        except asyncio.TimeoutError as exc:
            raise ProviderBrokerInvocationError("provider invocation exceeded broker timeout") from exc
        if result.cost_usd > granted_cost:
            raise ProviderBrokerInvocationError("provider result cost exceeded caller grant")
        if result.cost_usd > self.policy.max_cost_usd_per_request:
            raise ProviderBrokerInvocationError("provider result cost exceeded broker service ceiling")

        response_payload = {
            "protocol_version": _PROTOCOL_VERSION,
            "request_id": request_id,
            "binding_digest": self.binding.binding_digest,
            "provider_profile": self.binding.provider_profile,
            "provider_family": self.binding.provider_family,
            "model_selector": self.binding.model_selector,
            "decision": result.decision,
            "usage": {
                "input_tokens": result.input_tokens,
                "output_tokens": result.output_tokens,
                "cost_usd": format(result.cost_usd, "f"),
            },
        }
        _validate_with_schema(self._response_validator, response_payload, context="broker response")
        response_body = _canonical_json(response_payload)
        if len(response_body) > self.policy.max_response_bytes:
            raise ProviderBrokerInvocationError("broker response exceeds server byte cap")

        candidate = IdempotencyRecord(
            request_digest=request_digest,
            response=response_body,
        )
        stored = self.idempotency_store.put_if_absent(request_id, candidate)
        if stored.request_digest != request_digest:
            raise ProviderBrokerIdempotencyConflict(
                "idempotency key was concurrently reused with different request bytes"
            )
        return BrokerHTTPResponse(status_code=200, body=stored.response)
