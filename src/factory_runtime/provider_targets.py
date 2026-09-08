"""Registry-backed provider target selection and zero-cost dry-run invocation.

This module implements the server-side seam behind the provider broker without
activating any paid or live provider traffic. The Factory model selector resolves
through a checked-in allowlisted catalog. The dry-run invoker accepts only
``dry-run://`` targets, owns no vendor credential, performs no network I/O, and
always reports zero provider cost.

A later live-provider implementation may satisfy the same ProviderInvoker
protocol, but must be introduced as a separate owner-reviewed change.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from decimal import Decimal
from pathlib import Path
from typing import Any, Protocol

import yaml

from .provider_broker_service import (
    ProviderBrokerInvocationError,
    ProviderInvocationResult,
    ProviderInvoker,
    ProviderSelectorResolver,
    ResolvedProviderTarget,
)


_CATALOG_PATH = "factory/profiles/provider-models.yaml"
_EXPECTED_SCHEMA_VERSION = "1.0"
_EXPECTED_AUTHORITY_EFFECT = "none"
_DRY_RUN_SCHEME = "dry-run://"


class ProviderTargetConfigError(ProviderBrokerInvocationError):
    """Raised when the checked-in target catalog is malformed or inconsistent."""


class ProviderSelectorValueSource(Protocol):
    """Resolve a symbolic Factory selector to one approved catalog target alias."""

    def get(self, selector: str) -> str:
        ...


@dataclass(frozen=True)
class StaticProviderSelectorValueSource:
    """Explicit selector values for dry-run tests and controlled composition."""

    values: dict[str, str]

    def get(self, selector: str) -> str:
        if not isinstance(selector, str) or not selector:
            raise ProviderTargetConfigError("model selector must be a nonempty string")
        value = self.values.get(selector)
        if not isinstance(value, str) or not value:
            raise ProviderTargetConfigError(f"model selector has no configured target: {selector}")
        return value


@dataclass(frozen=True)
class ProviderTargetCatalogEntry:
    alias: str
    provider_family: str
    model_id: str
    execution_mode: str
    selector_version: str
    enabled: bool
    live_credentials: str
    cost_mode: str


class CatalogProviderSelectorResolver(ProviderSelectorResolver):
    """Resolve Factory symbolic model selectors through a fail-closed catalog."""

    def __init__(
        self,
        factory_repository_root: Path,
        selector_values: ProviderSelectorValueSource,
        *,
        catalog_relative_path: str = _CATALOG_PATH,
    ) -> None:
        self.factory_repository_root = factory_repository_root.resolve()
        self.selector_values = selector_values
        self.catalog_relative_path = catalog_relative_path
        self._selectors, self._targets = self._load_catalog()

    def _load_catalog(self) -> tuple[dict[str, dict[str, Any]], dict[str, ProviderTargetCatalogEntry]]:
        path = self.factory_repository_root / self.catalog_relative_path
        try:
            raw = path.read_bytes()
        except OSError as exc:
            raise ProviderTargetConfigError("provider target catalog cannot be read") from exc
        try:
            parsed = yaml.safe_load(raw)
        except yaml.YAMLError as exc:
            raise ProviderTargetConfigError("provider target catalog is invalid YAML") from exc
        if not isinstance(parsed, dict):
            raise ProviderTargetConfigError("provider target catalog must be a mapping")
        if parsed.get("schema_version") != _EXPECTED_SCHEMA_VERSION:
            raise ProviderTargetConfigError("provider target catalog schema_version is unsupported")
        if set(parsed) != {"schema_version", "selectors", "targets"}:
            raise ProviderTargetConfigError("provider target catalog contains unknown top-level fields")

        selectors = parsed.get("selectors")
        targets = parsed.get("targets")
        if not isinstance(selectors, dict) or not selectors:
            raise ProviderTargetConfigError("provider target catalog selectors mapping is missing")
        if not isinstance(targets, dict) or not targets:
            raise ProviderTargetConfigError("provider target catalog targets mapping is missing")

        normalized_selectors: dict[str, dict[str, Any]] = {}
        for selector, config in selectors.items():
            if not isinstance(selector, str) or not selector or not isinstance(config, dict):
                raise ProviderTargetConfigError("provider selector entry is invalid")
            expected_keys = {
                "provider_profile",
                "provider_family",
                "allowed_targets",
                "default_target",
                "authority_effect",
            }
            if set(config) != expected_keys:
                raise ProviderTargetConfigError(f"provider selector {selector} has unknown/missing fields")
            if config.get("authority_effect") != _EXPECTED_AUTHORITY_EFFECT:
                raise ProviderTargetConfigError(f"provider selector {selector} must have no authority effect")
            for field in ("provider_profile", "provider_family", "default_target"):
                value = config.get(field)
                if not isinstance(value, str) or not value:
                    raise ProviderTargetConfigError(f"provider selector {selector} has invalid {field}")
            allowed = config.get("allowed_targets")
            if (
                not isinstance(allowed, list)
                or not allowed
                or any(not isinstance(item, str) or not item for item in allowed)
                or len(set(allowed)) != len(allowed)
            ):
                raise ProviderTargetConfigError(f"provider selector {selector} has invalid allowed_targets")
            if config["default_target"] not in allowed:
                raise ProviderTargetConfigError(f"provider selector {selector} default is not allowlisted")
            normalized_selectors[selector] = dict(config)

        normalized_targets: dict[str, ProviderTargetCatalogEntry] = {}
        for alias, config in targets.items():
            if not isinstance(alias, str) or not alias or not isinstance(config, dict):
                raise ProviderTargetConfigError("provider target entry is invalid")
            expected_keys = {
                "provider_family",
                "model_id",
                "execution_mode",
                "enabled",
                "live_credentials",
                "cost_mode",
                "selector_version",
            }
            if set(config) != expected_keys:
                raise ProviderTargetConfigError(f"provider target {alias} has unknown/missing fields")
            for field in (
                "provider_family",
                "model_id",
                "execution_mode",
                "live_credentials",
                "cost_mode",
                "selector_version",
            ):
                value = config.get(field)
                if not isinstance(value, str) or not value:
                    raise ProviderTargetConfigError(f"provider target {alias} has invalid {field}")
            if not isinstance(config.get("enabled"), bool):
                raise ProviderTargetConfigError(f"provider target {alias} enabled must be boolean")
            entry = ProviderTargetCatalogEntry(
                alias=alias,
                provider_family=config["provider_family"],
                model_id=config["model_id"],
                execution_mode=config["execution_mode"],
                selector_version=config["selector_version"],
                enabled=config["enabled"],
                live_credentials=config["live_credentials"],
                cost_mode=config["cost_mode"],
            )
            normalized_targets[alias] = entry

        for selector, config in normalized_selectors.items():
            family = config["provider_family"]
            for alias in config["allowed_targets"]:
                target = normalized_targets.get(alias)
                if target is None:
                    raise ProviderTargetConfigError(
                        f"provider selector {selector} references missing target {alias}"
                    )
                if target.provider_family != family:
                    raise ProviderTargetConfigError(
                        f"provider selector {selector} target family does not match selector family"
                    )

        return normalized_selectors, normalized_targets

    def resolve(
        self,
        *,
        provider_profile: str,
        provider_family: str,
        model_selector: str,
    ) -> ResolvedProviderTarget:
        selector = self._selectors.get(model_selector)
        if selector is None:
            raise ProviderTargetConfigError("provider model selector is not present in approved catalog")
        if selector["provider_profile"] != provider_profile:
            raise ProviderTargetConfigError("provider profile does not match target catalog selector")
        if selector["provider_family"] != provider_family:
            raise ProviderTargetConfigError("provider family does not match target catalog selector")

        alias = self.selector_values.get(model_selector)
        if alias not in selector["allowed_targets"]:
            raise ProviderTargetConfigError("selected provider target is not allowlisted for selector")
        target = self._targets.get(alias)
        if target is None:
            raise ProviderTargetConfigError("selected provider target does not exist")
        if not target.enabled:
            raise ProviderTargetConfigError("selected provider target is disabled")
        if target.provider_family != provider_family:
            raise ProviderTargetConfigError("selected provider target family mismatch")

        # This implementation is intentionally dry-run only. A live target must
        # not silently pass through this resolver path.
        if target.execution_mode != "dry_run":
            raise ProviderTargetConfigError("selected target is not approved for dry-run execution")
        if not target.model_id.startswith(_DRY_RUN_SCHEME):
            raise ProviderTargetConfigError("dry-run target model_id must use dry-run:// scheme")
        if target.live_credentials != "prohibited":
            raise ProviderTargetConfigError("dry-run target must prohibit live credentials")
        if target.cost_mode != "zero":
            raise ProviderTargetConfigError("dry-run target must use zero cost mode")

        return ResolvedProviderTarget(
            provider_family=target.provider_family,
            model_id=target.model_id,
            selector_version=target.selector_version,
        )


class DryRunDecisionEngine(Protocol):
    """Produce one structured provider decision without network/provider access."""

    async def decide(
        self,
        *,
        target: ResolvedProviderTarget,
        turn: dict[str, Any],
        decision_schema_version: str,
    ) -> dict[str, Any]:
        ...


@dataclass
class ScriptedDryRunDecisionEngine:
    """Deterministic FIFO decision engine for conformance/dry-run exercises."""

    decisions: list[dict[str, Any]]

    async def decide(
        self,
        *,
        target: ResolvedProviderTarget,
        turn: dict[str, Any],
        decision_schema_version: str,
    ) -> dict[str, Any]:
        if not self.decisions:
            raise ProviderBrokerInvocationError("dry-run decision script is exhausted")
        decision = self.decisions.pop(0)
        if not isinstance(decision, dict):
            raise ProviderBrokerInvocationError("dry-run decision must be an object")
        return decision


class DryRunProviderInvoker(ProviderInvoker):
    """Zero-cost invoker that mechanically refuses live provider targets."""

    def __init__(self, engine: DryRunDecisionEngine) -> None:
        self.engine = engine
        self.invocation_count = 0

    async def invoke(
        self,
        *,
        target: ResolvedProviderTarget,
        turn: dict[str, Any],
        max_cost_usd: Decimal,
        decision_schema_version: str,
    ) -> ProviderInvocationResult:
        if not isinstance(target, ResolvedProviderTarget):
            raise ProviderBrokerInvocationError("dry-run invoker requires a resolved provider target")
        if not target.model_id.startswith(_DRY_RUN_SCHEME):
            raise ProviderBrokerInvocationError("dry-run invoker refuses live provider model IDs")
        if not isinstance(max_cost_usd, Decimal) or not max_cost_usd.is_finite() or max_cost_usd <= 0:
            raise ProviderBrokerInvocationError("dry-run max_cost_usd must be a positive finite Decimal")
        if decision_schema_version != "1":
            raise ProviderBrokerInvocationError("dry-run invoker supports decision schema version 1 only")
        if not isinstance(turn, dict):
            raise ProviderBrokerInvocationError("dry-run provider turn must be an object")

        # Canonical serialization is used only to generate deterministic synthetic
        # usage counters; no data leaves this process.
        encoded = json.dumps(turn, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
            "utf-8"
        )
        input_tokens = max(1, (len(encoded) + 3) // 4)
        decision = await self.engine.decide(
            target=target,
            turn=turn,
            decision_schema_version=decision_schema_version,
        )
        output_bytes = json.dumps(
            decision,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
        output_tokens = max(1, (len(output_bytes) + 3) // 4)
        self.invocation_count += 1
        return ProviderInvocationResult(
            decision=decision,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            cost_usd=Decimal("0.00"),
        )


def build_dry_run_provider_backend(
    factory_repository_root: Path,
    *,
    selector_values: ProviderSelectorValueSource,
    decision_engine: DryRunDecisionEngine,
) -> tuple[CatalogProviderSelectorResolver, DryRunProviderInvoker]:
    """Construct the approved zero-cost selector/invoker pair for dry runs."""

    resolver = CatalogProviderSelectorResolver(factory_repository_root, selector_values)
    invoker = DryRunProviderInvoker(decision_engine)
    return resolver, invoker
