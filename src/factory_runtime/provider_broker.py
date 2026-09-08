"""Provider-broker adapter for the structured CI repair model.

The repair runtime never calls a model vendor directly. This module binds the
engineering-agent repair model to the Factory registry, requires the internal
HTTPS provider broker, obtains an audience-scoped ephemeral broker credential
for each call, sends a deterministic structured request, and parses only a
strict repair decision response.

The broker may route to any configured provider/model behind the registry's
model selector. Provider calls have no Factory authority effect. The adapter has
no GitHub, shell, release, or state-mutation capability.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import math
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any, Protocol
from urllib.parse import urlparse

import yaml

from .structured_repair import (
    ApplyEditsDecision,
    EscalateDecision,
    LiteralReplaceEdit,
    ReadFilesDecision,
    RepairModel,
    RepairModelDecision,
    RepairModelTurn,
)


_PROTOCOL_VERSION = "factory-repair-broker-v1"
_DEFAULT_ENDPOINT = "https://provider-broker.internal/v1/repair/decide"
_EXPECTED_ROLE = "engineering_agent"
_EXPECTED_SECRET_POLICY = "brokered_ephemeral_only"
_EXPECTED_BROKER_SECRET = "provider_broker_token"
_DIRECT_PROVIDER_HOSTS = frozenset(
    {
        "api.openai.com",
        "api.anthropic.com",
        "generativelanguage.googleapis.com",
        "aiplatform.googleapis.com",
    }
)


class ProviderBrokerError(RuntimeError):
    """Base class for broker adapter failures."""


class ProviderBrokerConfigError(ProviderBrokerError):
    """Raised when registry/network/provider bindings are inconsistent."""


class ProviderBrokerCredentialError(ProviderBrokerError):
    """Raised when an ephemeral broker credential is invalid or unavailable."""


class ProviderBrokerProtocolError(ProviderBrokerError):
    """Raised when broker transport or response validation fails."""


class ProviderBrokerBudgetError(ProviderBrokerError):
    """Raised when a broker call would exceed the configured spend budget."""


def _aware(value: datetime) -> bool:
    return value.tzinfo is not None and value.utcoffset() is not None


def _canonical_json(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def _sha256(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _read_yaml(path: Path) -> tuple[bytes, dict[str, Any]]:
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise ProviderBrokerConfigError(f"cannot read Factory config: {path}") from exc
    try:
        parsed = yaml.safe_load(raw)
    except yaml.YAMLError as exc:
        raise ProviderBrokerConfigError(f"invalid YAML in Factory config: {path}") from exc
    if not isinstance(parsed, dict):
        raise ProviderBrokerConfigError(f"Factory config must be a mapping: {path}")
    return raw, parsed


def _validate_endpoint(endpoint: str) -> None:
    if not isinstance(endpoint, str):
        raise ProviderBrokerConfigError("provider broker endpoint must be a string")
    parsed = urlparse(endpoint)
    if parsed.scheme != "https":
        raise ProviderBrokerConfigError("provider broker endpoint must use HTTPS")
    if parsed.hostname != "provider-broker.internal":
        raise ProviderBrokerConfigError("provider broker endpoint must use provider-broker.internal")
    if parsed.port not in (None, 443):
        raise ProviderBrokerConfigError("provider broker endpoint must use port 443")
    if parsed.username is not None or parsed.password is not None:
        raise ProviderBrokerConfigError("provider broker endpoint may not contain credentials")
    if parsed.query or parsed.fragment:
        raise ProviderBrokerConfigError("provider broker endpoint may not contain query or fragment")
    if parsed.path != "/v1/repair/decide":
        raise ProviderBrokerConfigError("provider broker endpoint path is not approved")


@dataclass(frozen=True)
class ProviderBrokerBinding:
    """Registry-derived non-authoritative provider binding."""

    role_id: str
    provider_profile: str
    provider_family: str
    model_selector: str
    network_policy: str
    endpoint: str
    binding_digest: str


def load_provider_broker_binding(
    repository_root: Path,
    *,
    endpoint: str = _DEFAULT_ENDPOINT,
) -> ProviderBrokerBinding:
    """Load and verify the repair model's Factory registry/network binding."""

    _validate_endpoint(endpoint)
    root = repository_root.resolve()
    role_path = root / "factory" / "roles" / "engineering_agent.yaml"
    providers_path = root / "factory" / "profiles" / "providers.yaml"
    networks_path = root / "factory" / "profiles" / "networks.yaml"
    credentials_path = root / "factory" / "profiles" / "credentials.yaml"

    role_raw, role = _read_yaml(role_path)
    providers_raw, providers = _read_yaml(providers_path)
    networks_raw, networks = _read_yaml(networks_path)
    credentials_raw, credentials = _read_yaml(credentials_path)

    if role.get("role_id") != _EXPECTED_ROLE:
        raise ProviderBrokerConfigError("engineering-agent role identity is not bound correctly")
    provider_profile = role.get("provider_profile")
    network_policy = role.get("network_policy")
    if not isinstance(provider_profile, str) or not provider_profile:
        raise ProviderBrokerConfigError("engineering agent lacks a provider profile")
    if not isinstance(network_policy, str) or not network_policy:
        raise ProviderBrokerConfigError("engineering agent lacks a network policy")
    if role.get("secret_policy") != _EXPECTED_SECRET_POLICY:
        raise ProviderBrokerConfigError("engineering agent must require brokered ephemeral secrets")

    profile_map = providers.get("profiles")
    if not isinstance(profile_map, dict):
        raise ProviderBrokerConfigError("provider profiles mapping is missing")
    profile = profile_map.get(provider_profile)
    if not isinstance(profile, dict):
        raise ProviderBrokerConfigError("engineering-agent provider profile does not exist")
    provider_family = profile.get("provider_family")
    model_selector = profile.get("model_selector")
    if not isinstance(provider_family, str) or not provider_family:
        raise ProviderBrokerConfigError("provider family is invalid")
    if not isinstance(model_selector, str) or not model_selector:
        raise ProviderBrokerConfigError("model selector is invalid")
    if profile.get("authority_effect") != "none":
        raise ProviderBrokerConfigError("repair provider profile must have no authority effect")

    network_map = networks.get("profiles")
    if not isinstance(network_map, dict):
        raise ProviderBrokerConfigError("network profiles mapping is missing")
    selected_network = network_map.get(network_policy)
    if not isinstance(selected_network, dict):
        raise ProviderBrokerConfigError("engineering-agent network policy does not exist")
    allow = selected_network.get("allow")
    if not isinstance(allow, list) or not all(isinstance(item, str) for item in allow):
        raise ProviderBrokerConfigError("engineering-agent network allowlist is invalid")
    if "provider-broker.internal:443" not in allow:
        raise ProviderBrokerConfigError("engineering-agent network policy does not allow provider broker")
    for item in allow:
        host = item.rsplit(":", 1)[0].lower()
        if host in _DIRECT_PROVIDER_HOSTS:
            raise ProviderBrokerConfigError("engineering-agent network policy permits a direct provider endpoint")

    credential_profiles = credentials.get("profiles")
    if not isinstance(credential_profiles, dict):
        raise ProviderBrokerConfigError("credential profiles mapping is missing")
    controller = credential_profiles.get("controller_service")
    if not isinstance(controller, dict):
        raise ProviderBrokerConfigError("controller credential profile is missing")
    controller_secrets = controller.get("secrets")
    if not isinstance(controller_secrets, list) or _EXPECTED_BROKER_SECRET not in controller_secrets:
        raise ProviderBrokerConfigError("controller does not expose the broker-token issuance path")

    binding_material = {
        "protocol": _PROTOCOL_VERSION,
        "endpoint": endpoint,
        "role_file": _sha256(role_raw),
        "providers_file": _sha256(providers_raw),
        "networks_file": _sha256(networks_raw),
        "credentials_file": _sha256(credentials_raw),
        "role_id": _EXPECTED_ROLE,
        "provider_profile": provider_profile,
        "provider_family": provider_family,
        "model_selector": model_selector,
        "network_policy": network_policy,
    }
    return ProviderBrokerBinding(
        role_id=_EXPECTED_ROLE,
        provider_profile=provider_profile,
        provider_family=provider_family,
        model_selector=model_selector,
        network_policy=network_policy,
        endpoint=endpoint,
        binding_digest=_sha256(_canonical_json(binding_material)),
    )


@dataclass(frozen=True)
class ProviderBrokerBudget:
    """Caller-owned spend and transport ceilings for one model instance."""

    max_cost_usd_per_call: Decimal
    max_total_cost_usd: Decimal
    max_request_bytes: int = 256 * 1024
    max_response_bytes: int = 64 * 1024
    timeout_seconds: int = 60
    max_credential_ttl_seconds: int = 900

    def __post_init__(self) -> None:
        for name in ("max_cost_usd_per_call", "max_total_cost_usd"):
            value = getattr(self, name)
            if not isinstance(value, Decimal) or not value.is_finite() or value <= 0:
                raise ProviderBrokerBudgetError(f"{name} must be a positive finite Decimal")
        if self.max_cost_usd_per_call > self.max_total_cost_usd:
            raise ProviderBrokerBudgetError("per-call cost ceiling may not exceed total cost ceiling")
        bounds = (
            ("max_request_bytes", self.max_request_bytes, 1024, 1024 * 1024),
            ("max_response_bytes", self.max_response_bytes, 1024, 1024 * 1024),
            ("timeout_seconds", self.timeout_seconds, 1, 180),
            ("max_credential_ttl_seconds", self.max_credential_ttl_seconds, 30, 3600),
        )
        for name, value, low, high in bounds:
            if isinstance(value, bool) or not isinstance(value, int) or value < low or value > high:
                raise ProviderBrokerBudgetError(f"{name} must be between {low} and {high}")


@dataclass(frozen=True)
class EphemeralBrokerCredential:
    """Audience-scoped short-lived credential issued by the Factory broker path."""

    token: str
    audience: str
    issued_at: datetime
    expires_at: datetime


class BrokerCredentialSource(Protocol):
    async def issue(self, *, audience: str) -> EphemeralBrokerCredential:
        ...


@dataclass(frozen=True)
class BrokerHTTPResponse:
    status_code: int
    body: bytes


class BrokerTransport(Protocol):
    async def post_json(
        self,
        *,
        endpoint: str,
        headers: dict[str, str],
        body: bytes,
        timeout_seconds: int,
    ) -> BrokerHTTPResponse:
        ...


@dataclass(frozen=True)
class ProviderBrokerUsage:
    input_tokens: int
    output_tokens: int
    cost_usd: Decimal


@dataclass(frozen=True)
class ProviderBrokerCallRecord:
    request_id: str
    provider_profile: str
    provider_family: str
    model_selector: str
    usage: ProviderBrokerUsage


def _decision_payload(turn: RepairModelTurn) -> dict[str, Any]:
    return {
        "repair_id": turn.repair_id,
        "attempt_number": turn.attempt_number,
        "turn_number": turn.turn_number,
        "original_command": list(turn.original_command),
        "stdout_excerpt": turn.stdout_excerpt,
        "stderr_excerpt": turn.stderr_excerpt,
        "diagnostic_redaction_count": turn.diagnostic_redaction_count,
        "inventory": list(turn.inventory),
        "files": [
            {
                "path": item.path,
                "content_digest": item.content_digest,
                "content": item.content,
                "redaction_count": item.redaction_count,
                "truncated": item.truncated,
            }
            for item in turn.files
        ],
    }


def _exact_keys(value: dict[str, Any], expected: set[str], context: str) -> None:
    actual = set(value)
    if actual != expected:
        missing = sorted(expected - actual)
        extra = sorted(actual - expected)
        raise ProviderBrokerProtocolError(
            f"{context} keys are invalid (missing={missing}, extra={extra})"
        )


def _parse_nonnegative_int(value: Any, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ProviderBrokerProtocolError(f"{field} must be a nonnegative integer")
    return value


def _parse_cost(value: Any) -> Decimal:
    if not isinstance(value, str):
        raise ProviderBrokerProtocolError("reported cost_usd must be a decimal string")
    try:
        parsed = Decimal(value)
    except InvalidOperation as exc:
        raise ProviderBrokerProtocolError("reported cost_usd is invalid") from exc
    if not parsed.is_finite() or parsed < 0:
        raise ProviderBrokerProtocolError("reported cost_usd must be finite and nonnegative")
    return parsed


def _parse_decision(value: Any) -> RepairModelDecision:
    if not isinstance(value, dict):
        raise ProviderBrokerProtocolError("broker decision must be an object")
    decision_type = value.get("type")
    if decision_type == "read_files":
        _exact_keys(value, {"type", "paths"}, "read_files decision")
        paths = value["paths"]
        if not isinstance(paths, list) or not all(isinstance(item, str) for item in paths):
            raise ProviderBrokerProtocolError("read_files paths must be strings")
        return ReadFilesDecision(paths=tuple(paths))
    if decision_type == "apply_edits":
        _exact_keys(value, {"type", "summary", "edits"}, "apply_edits decision")
        summary = value["summary"]
        edits = value["edits"]
        if not isinstance(summary, str):
            raise ProviderBrokerProtocolError("apply_edits summary must be a string")
        if not isinstance(edits, list):
            raise ProviderBrokerProtocolError("apply_edits edits must be an array")
        parsed_edits: list[LiteralReplaceEdit] = []
        for index, edit in enumerate(edits):
            if not isinstance(edit, dict):
                raise ProviderBrokerProtocolError(f"edit {index} must be an object")
            _exact_keys(edit, {"path", "old_text", "new_text"}, f"edit {index}")
            if not all(isinstance(edit[key], str) for key in ("path", "old_text", "new_text")):
                raise ProviderBrokerProtocolError(f"edit {index} fields must be strings")
            parsed_edits.append(
                LiteralReplaceEdit(
                    path=edit["path"],
                    old_text=edit["old_text"],
                    new_text=edit["new_text"],
                )
            )
        return ApplyEditsDecision(summary=summary, edits=tuple(parsed_edits))
    if decision_type == "escalate":
        _exact_keys(value, {"type", "reason"}, "escalate decision")
        reason = value["reason"]
        if not isinstance(reason, str):
            raise ProviderBrokerProtocolError("escalation reason must be a string")
        return EscalateDecision(reason=reason)
    raise ProviderBrokerProtocolError("broker returned an unsupported repair decision type")


class ProviderBrokerRepairModel(RepairModel):
    """Structured repair model implemented through the Factory provider broker."""

    def __init__(
        self,
        binding: ProviderBrokerBinding,
        credential_source: BrokerCredentialSource,
        transport: BrokerTransport,
        budget: ProviderBrokerBudget,
    ) -> None:
        _validate_endpoint(binding.endpoint)
        self.binding = binding
        self.credential_source = credential_source
        self.transport = transport
        self.budget = budget
        self._spent_usd = Decimal("0")
        self._records: list[ProviderBrokerCallRecord] = []
        self._lock = asyncio.Lock()

    @property
    def spent_usd(self) -> Decimal:
        return self._spent_usd

    @property
    def call_records(self) -> tuple[ProviderBrokerCallRecord, ...]:
        return tuple(self._records)

    def _validate_credential(
        self,
        credential: EphemeralBrokerCredential,
        *,
        now: datetime,
    ) -> None:
        if not isinstance(credential.token, str) or len(credential.token) < 16:
            raise ProviderBrokerCredentialError("broker credential token is invalid")
        if any(ord(ch) < 33 or ord(ch) > 126 for ch in credential.token):
            raise ProviderBrokerCredentialError("broker credential token contains invalid characters")
        if credential.audience != "provider-broker.internal":
            raise ProviderBrokerCredentialError("broker credential audience is invalid")
        if not _aware(credential.issued_at) or not _aware(credential.expires_at):
            raise ProviderBrokerCredentialError("broker credential timestamps must be timezone-aware")
        if credential.issued_at > now + timedelta(seconds=30):
            raise ProviderBrokerCredentialError("broker credential is future-issued")
        if credential.expires_at <= now:
            raise ProviderBrokerCredentialError("broker credential is expired")
        ttl = (credential.expires_at - credential.issued_at).total_seconds()
        if ttl <= 0 or ttl > self.budget.max_credential_ttl_seconds:
            raise ProviderBrokerCredentialError("broker credential lifetime exceeds ephemeral policy")

    def _build_request(self, turn: RepairModelTurn, granted_cost: Decimal) -> tuple[str, bytes]:
        turn_payload = _decision_payload(turn)
        request_seed = {
            "protocol_version": _PROTOCOL_VERSION,
            "binding_digest": self.binding.binding_digest,
            "role_id": self.binding.role_id,
            "provider_profile": self.binding.provider_profile,
            "provider_family": self.binding.provider_family,
            "model_selector": self.binding.model_selector,
            "task": "structured_ci_repair_decision",
            "decision_schema_version": "1",
            "turn": turn_payload,
        }
        request_id = _sha256(_canonical_json(request_seed))
        payload = {
            **request_seed,
            "request_id": request_id,
            "idempotency_key": request_id,
            "budget": {
                "max_cost_usd": format(granted_cost, "f"),
            },
        }
        body = _canonical_json(payload)
        if len(body) > self.budget.max_request_bytes:
            raise ProviderBrokerProtocolError("provider-broker request exceeds configured byte cap")
        return request_id, body

    def _parse_response(
        self,
        *,
        request_id: str,
        response: BrokerHTTPResponse,
        granted_cost: Decimal,
    ) -> tuple[RepairModelDecision, ProviderBrokerUsage]:
        if isinstance(response.status_code, bool) or not isinstance(response.status_code, int):
            raise ProviderBrokerProtocolError("broker returned an invalid HTTP status")
        if response.status_code != 200:
            raise ProviderBrokerProtocolError(f"provider broker returned HTTP {response.status_code}")
        if not isinstance(response.body, bytes):
            raise ProviderBrokerProtocolError("broker response body must be bytes")
        if len(response.body) > self.budget.max_response_bytes:
            raise ProviderBrokerProtocolError("provider-broker response exceeds configured byte cap")
        try:
            decoded = response.body.decode("utf-8")
            parsed = json.loads(decoded)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ProviderBrokerProtocolError("broker returned invalid JSON") from exc
        if not isinstance(parsed, dict):
            raise ProviderBrokerProtocolError("broker response must be an object")
        _exact_keys(
            parsed,
            {
                "protocol_version",
                "request_id",
                "binding_digest",
                "provider_profile",
                "provider_family",
                "model_selector",
                "decision",
                "usage",
            },
            "broker response",
        )
        expected_pairs = {
            "protocol_version": _PROTOCOL_VERSION,
            "request_id": request_id,
            "binding_digest": self.binding.binding_digest,
            "provider_profile": self.binding.provider_profile,
            "provider_family": self.binding.provider_family,
            "model_selector": self.binding.model_selector,
        }
        for field, expected in expected_pairs.items():
            if parsed[field] != expected:
                raise ProviderBrokerProtocolError(f"broker response {field} does not match request")

        usage_raw = parsed["usage"]
        if not isinstance(usage_raw, dict):
            raise ProviderBrokerProtocolError("broker usage must be an object")
        _exact_keys(usage_raw, {"input_tokens", "output_tokens", "cost_usd"}, "broker usage")
        usage = ProviderBrokerUsage(
            input_tokens=_parse_nonnegative_int(usage_raw["input_tokens"], "input_tokens"),
            output_tokens=_parse_nonnegative_int(usage_raw["output_tokens"], "output_tokens"),
            cost_usd=_parse_cost(usage_raw["cost_usd"]),
        )
        if usage.cost_usd > granted_cost:
            raise ProviderBrokerBudgetError("broker reported cost above the granted per-call budget")
        return _parse_decision(parsed["decision"]), usage

    async def decide(self, turn: RepairModelTurn) -> RepairModelDecision:
        # Serialize calls so cumulative spend checks cannot race inside one model instance.
        async with self._lock:
            remaining = self.budget.max_total_cost_usd - self._spent_usd
            if remaining <= 0:
                raise ProviderBrokerBudgetError("provider-broker total cost budget is exhausted")
            granted = min(self.budget.max_cost_usd_per_call, remaining)
            request_id, body = self._build_request(turn, granted)

            now = datetime.now(timezone.utc)
            credential = await self.credential_source.issue(audience="provider-broker.internal")
            self._validate_credential(credential, now=now)

            headers = {
                "Authorization": f"Bearer {credential.token}",
                "Content-Type": "application/json",
                "Accept": "application/json",
                "X-Factory-Binding-Digest": self.binding.binding_digest,
                "Idempotency-Key": request_id,
            }
            response = await self.transport.post_json(
                endpoint=self.binding.endpoint,
                headers=headers,
                body=body,
                timeout_seconds=self.budget.timeout_seconds,
            )
            decision, usage = self._parse_response(
                request_id=request_id,
                response=response,
                granted_cost=granted,
            )
            projected = self._spent_usd + usage.cost_usd
            if projected > self.budget.max_total_cost_usd:
                raise ProviderBrokerBudgetError("broker response would exceed the total cost budget")
            self._spent_usd = projected
            self._records.append(
                ProviderBrokerCallRecord(
                    request_id=request_id,
                    provider_profile=self.binding.provider_profile,
                    provider_family=self.binding.provider_family,
                    model_selector=self.binding.model_selector,
                    usage=usage,
                )
            )
            return decision
