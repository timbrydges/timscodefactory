from __future__ import annotations

import asyncio
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from factory_runtime.provider_broker import (  # noqa: E402
    BrokerHTTPResponse,
    EphemeralBrokerCredential,
    ProviderBrokerBudget,
    ProviderBrokerRepairModel,
    load_provider_broker_binding,
)
from factory_runtime.provider_broker_service import (  # noqa: E402
    BrokerAuthContext,
    BrokerServicePolicy,
    ProviderBrokerInvocationError,
    ReferenceProviderBrokerService,
    ResolvedProviderTarget,
)
from factory_runtime.provider_targets import (  # noqa: E402
    CatalogProviderSelectorResolver,
    DryRunProviderInvoker,
    ProviderTargetConfigError,
    ScriptedDryRunDecisionEngine,
    StaticProviderSelectorValueSource,
    build_dry_run_provider_backend,
)
from factory_runtime.structured_repair import RepairModelTurn  # noqa: E402


ROOT = Path(__file__).resolve().parents[1]


def turn() -> RepairModelTurn:
    return RepairModelTurn(
        repair_id="repair-dry-run-1",
        attempt_number=1,
        turn_number=1,
        original_command=("python", "-m", "pytest", "-q"),
        stdout_excerpt="",
        stderr_excerpt="AssertionError: expected 2",
        diagnostic_redaction_count=0,
        inventory=("app.py",),
        files=(),
    )


class StaticCredentialSource:
    async def issue(self, *, audience: str) -> EphemeralBrokerCredential:
        now = datetime.now(timezone.utc)
        return EphemeralBrokerCredential(
            token="broker-test-token-1234567890",
            audience=audience,
            issued_at=now - timedelta(seconds=1),
            expires_at=now + timedelta(minutes=5),
        )


class ServiceTransport:
    def __init__(self, service: ReferenceProviderBrokerService) -> None:
        self.service = service

    async def post_json(
        self,
        *,
        endpoint: str,
        headers: dict[str, str],
        body: bytes,
        timeout_seconds: int,
    ) -> BrokerHTTPResponse:
        del endpoint, timeout_seconds
        self.asserted_authorization = headers.get("Authorization")
        now = datetime.now(timezone.utc)
        return await self.service.handle(
            body=body,
            auth=BrokerAuthContext(
                subject="engineering_agent_service",
                audience="provider-broker.internal",
                issued_at=now - timedelta(seconds=1),
                expires_at=now + timedelta(minutes=5),
            ),
            now=now,
        )


class ProviderTargetTests(unittest.TestCase):
    def test_live_factory_catalog_resolves_only_dry_run_coding_target(self):
        resolver = CatalogProviderSelectorResolver(
            ROOT,
            StaticProviderSelectorValueSource(
                {"FACTORY_CODING_MODEL": "coding_primary_dry_run"}
            ),
        )
        target = resolver.resolve(
            provider_profile="coding_primary",
            provider_family="openai",
            model_selector="FACTORY_CODING_MODEL",
        )
        self.assertEqual(target.provider_family, "openai")
        self.assertEqual(target.model_id, "dry-run://coding-primary")
        self.assertEqual(target.selector_version, "dry-run-v1")

    def test_unapproved_target_alias_fails_closed(self):
        resolver = CatalogProviderSelectorResolver(
            ROOT,
            StaticProviderSelectorValueSource(
                {"FACTORY_CODING_MODEL": "not-approved"}
            ),
        )
        with self.assertRaises(ProviderTargetConfigError):
            resolver.resolve(
                provider_profile="coding_primary",
                provider_family="openai",
                model_selector="FACTORY_CODING_MODEL",
            )

    def test_provider_profile_or_family_drift_fails_closed(self):
        resolver = CatalogProviderSelectorResolver(
            ROOT,
            StaticProviderSelectorValueSource(
                {"FACTORY_CODING_MODEL": "coding_primary_dry_run"}
            ),
        )
        with self.assertRaises(ProviderTargetConfigError):
            resolver.resolve(
                provider_profile="reasoning_primary",
                provider_family="openai",
                model_selector="FACTORY_CODING_MODEL",
            )
        with self.assertRaises(ProviderTargetConfigError):
            resolver.resolve(
                provider_profile="coding_primary",
                provider_family="anthropic",
                model_selector="FACTORY_CODING_MODEL",
            )

    def test_catalog_rejects_live_target_on_dry_run_path(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            path = root / "factory" / "profiles"
            path.mkdir(parents=True)
            catalog = yaml.safe_load(
                (ROOT / "factory/profiles/provider-models.yaml").read_text(encoding="utf-8")
            )
            catalog["targets"]["coding_primary_dry_run"]["execution_mode"] = "live"
            catalog["targets"]["coding_primary_dry_run"]["model_id"] = "some-live-model"
            catalog["targets"]["coding_primary_dry_run"]["live_credentials"] = "required"
            (path / "provider-models.yaml").write_text(
                yaml.safe_dump(catalog, sort_keys=False), encoding="utf-8"
            )
            resolver = CatalogProviderSelectorResolver(
                root,
                StaticProviderSelectorValueSource(
                    {"FACTORY_CODING_MODEL": "coding_primary_dry_run"}
                ),
            )
            with self.assertRaises(ProviderTargetConfigError):
                resolver.resolve(
                    provider_profile="coding_primary",
                    provider_family="openai",
                    model_selector="FACTORY_CODING_MODEL",
                )

    def test_dry_run_invoker_reports_zero_cost_and_never_uses_live_target(self):
        engine = ScriptedDryRunDecisionEngine(
            [{"type": "read_files", "paths": ["app.py"]}]
        )
        resolver, invoker = build_dry_run_provider_backend(
            ROOT,
            selector_values=StaticProviderSelectorValueSource(
                {"FACTORY_CODING_MODEL": "coding_primary_dry_run"}
            ),
            decision_engine=engine,
        )
        target = resolver.resolve(
            provider_profile="coding_primary",
            provider_family="openai",
            model_selector="FACTORY_CODING_MODEL",
        )
        result = asyncio.run(
            invoker.invoke(
                target=target,
                turn={"repair_id": "r", "inventory": ["app.py"]},
                max_cost_usd=Decimal("0.25"),
                decision_schema_version="1",
            )
        )
        self.assertEqual(result.cost_usd, Decimal("0.00"))
        self.assertEqual(result.decision["type"], "read_files")
        self.assertEqual(invoker.invocation_count, 1)

        with self.assertRaises(ProviderBrokerInvocationError):
            asyncio.run(
                invoker.invoke(
                    target=ResolvedProviderTarget(
                        provider_family="openai",
                        model_id="live-model-id",
                        selector_version="live-v1",
                    ),
                    turn={},
                    max_cost_usd=Decimal("0.25"),
                    decision_schema_version="1",
                )
            )
        self.assertEqual(invoker.invocation_count, 1)

    def test_real_client_and_service_use_catalog_target_at_zero_cost(self):
        binding = load_provider_broker_binding(ROOT)
        resolver, invoker = build_dry_run_provider_backend(
            ROOT,
            selector_values=StaticProviderSelectorValueSource(
                {"FACTORY_CODING_MODEL": "coding_primary_dry_run"}
            ),
            decision_engine=ScriptedDryRunDecisionEngine(
                [{"type": "read_files", "paths": ["app.py"]}]
            ),
        )
        service = ReferenceProviderBrokerService(
            ROOT,
            binding,
            resolver,
            invoker,
            policy=BrokerServicePolicy(max_cost_usd_per_request=Decimal("0.50")),
        )
        transport = ServiceTransport(service)
        model = ProviderBrokerRepairModel(
            binding,
            StaticCredentialSource(),
            transport,
            ProviderBrokerBudget(
                max_cost_usd_per_call=Decimal("0.25"),
                max_total_cost_usd=Decimal("0.50"),
            ),
        )
        decision = asyncio.run(model.decide(turn()))
        self.assertEqual(tuple(decision.paths), ("app.py",))
        self.assertEqual(model.spent_usd, Decimal("0.00"))
        self.assertEqual(invoker.invocation_count, 1)
        self.assertTrue(transport.asserted_authorization.startswith("Bearer "))
        self.assertEqual(model.call_records[0].model_selector, "FACTORY_CODING_MODEL")
        self.assertEqual(model.call_records[0].usage.cost_usd, Decimal("0.00"))

    def test_catalog_top_level_unknown_field_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            path = root / "factory" / "profiles"
            path.mkdir(parents=True)
            catalog = yaml.safe_load(
                (ROOT / "factory/profiles/provider-models.yaml").read_text(encoding="utf-8")
            )
            catalog["surprise"] = True
            (path / "provider-models.yaml").write_text(
                yaml.safe_dump(catalog, sort_keys=False), encoding="utf-8"
            )
            with self.assertRaises(ProviderTargetConfigError):
                CatalogProviderSelectorResolver(
                    root,
                    StaticProviderSelectorValueSource(
                        {"FACTORY_CODING_MODEL": "coding_primary_dry_run"}
                    ),
                )


if __name__ == "__main__":
    unittest.main()
