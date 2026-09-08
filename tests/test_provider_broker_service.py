from __future__ import annotations

import asyncio
import json
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from factory_runtime.provider_broker import (  # noqa: E402
    EphemeralBrokerCredential,
    ProviderBrokerBudget,
    ProviderBrokerRepairModel,
    load_provider_broker_binding,
)
from factory_runtime.provider_broker_service import (  # noqa: E402
    BrokerAuthContext,
    BrokerServicePolicy,
    ProviderBrokerAuthenticationError,
    ProviderBrokerIdempotencyConflict,
    ProviderBrokerInvocationError,
    ProviderBrokerRequestError,
    ProviderInvocationResult,
    ReferenceProviderBrokerService,
    ResolvedProviderTarget,
    StaticProviderSelectorResolver,
)
from factory_runtime.structured_repair import (  # noqa: E402
    ApplyEditsDecision,
    ReadFilesDecision,
    RepairFileContext,
    RepairModelTurn,
)


class FakeCredentialSource:
    async def issue(self, *, audience: str) -> EphemeralBrokerCredential:
        now = datetime.now(timezone.utc)
        return EphemeralBrokerCredential(
            token="factory-broker-ephemeral-token-123456",
            audience=audience,
            issued_at=now - timedelta(seconds=1),
            expires_at=now + timedelta(minutes=5),
        )


class RecordingInvoker:
    def __init__(self, decision: dict | None = None, *, cost: Decimal = Decimal("0.01")) -> None:
        self.decision = decision or {"type": "read_files", "paths": ["src/app.py"]}
        self.cost = cost
        self.calls: list[dict] = []

    async def invoke(self, *, target, turn, max_cost_usd, decision_schema_version):
        self.calls.append(
            {
                "target": target,
                "turn": turn,
                "max_cost_usd": max_cost_usd,
                "decision_schema_version": decision_schema_version,
            }
        )
        return ProviderInvocationResult(
            decision=self.decision,
            input_tokens=100,
            output_tokens=25,
            cost_usd=self.cost,
        )


class SlowInvoker(RecordingInvoker):
    async def invoke(self, *, target, turn, max_cost_usd, decision_schema_version):
        await asyncio.sleep(0.05)
        return await super().invoke(
            target=target,
            turn=turn,
            max_cost_usd=max_cost_usd,
            decision_schema_version=decision_schema_version,
        )


class InProcessServiceTransport:
    """Client transport adapter that exercises the service core without a network."""

    def __init__(self, service: ReferenceProviderBrokerService, auth: BrokerAuthContext) -> None:
        self.service = service
        self.auth = auth
        self.calls: list[dict] = []
        self.last_body: bytes | None = None

    async def post_json(self, *, endpoint, headers, body, timeout_seconds):
        self.calls.append(
            {
                "endpoint": endpoint,
                "headers": dict(headers),
                "timeout_seconds": timeout_seconds,
            }
        )
        self.last_body = body
        return await self.service.handle(body=body, auth=self.auth)


def now_auth(**overrides) -> BrokerAuthContext:
    now = datetime.now(timezone.utc)
    values = {
        "subject": "engineering_agent_service",
        "audience": "provider-broker.internal",
        "issued_at": now - timedelta(seconds=1),
        "expires_at": now + timedelta(minutes=5),
    }
    values.update(overrides)
    return BrokerAuthContext(**values)


def repair_turn() -> RepairModelTurn:
    return RepairModelTurn(
        repair_id="repair-service-1",
        attempt_number=1,
        turn_number=1,
        original_command=("python", "-m", "pytest", "-q"),
        stdout_excerpt="1 failed",
        stderr_excerpt="AssertionError: expected 2, got 1",
        diagnostic_redaction_count=0,
        inventory=("src/app.py", "tests/test_app.py"),
        files=(
            RepairFileContext(
                path="src/app.py",
                content_digest="sha256:" + "a" * 64,
                content="def value():\n    return 1\n",
                redaction_count=0,
                truncated=False,
            ),
        ),
    )


def client_budget() -> ProviderBrokerBudget:
    return ProviderBrokerBudget(
        max_cost_usd_per_call=Decimal("0.20"),
        max_total_cost_usd=Decimal("0.50"),
    )


def resolver() -> StaticProviderSelectorResolver:
    return StaticProviderSelectorResolver(
        (
            (
                "coding_primary",
                "openai",
                "FACTORY_CODING_MODEL",
                "mock-coding-model-v1",
                "test-selector-v1",
            ),
        )
    )


class ProviderBrokerServiceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.root = Path(__file__).resolve().parents[1]
        cls.binding = load_provider_broker_binding(cls.root)

    def service(self, invoker=None, *, policy=None, selector=None):
        return ReferenceProviderBrokerService(
            self.root,
            self.binding,
            selector or resolver(),
            invoker or RecordingInvoker(),
            policy=policy,
        )

    def client(self, service, *, auth=None):
        transport = InProcessServiceTransport(service, auth or now_auth())
        model = ProviderBrokerRepairModel(
            self.binding,
            FakeCredentialSource(),
            transport,
            client_budget(),
        )
        return model, transport

    def test_client_and_service_protocol_conform_end_to_end(self):
        invoker = RecordingInvoker()
        service = self.service(invoker)
        model, transport = self.client(service)

        decision = asyncio.run(model.decide(repair_turn()))

        self.assertIsInstance(decision, ReadFilesDecision)
        self.assertEqual(decision.paths, ("src/app.py",))
        self.assertEqual(len(invoker.calls), 1)
        call = invoker.calls[0]
        self.assertEqual(call["target"].provider_family, "openai")
        self.assertEqual(call["target"].model_id, "mock-coding-model-v1")
        self.assertEqual(call["max_cost_usd"], Decimal("0.20"))
        self.assertEqual(call["decision_schema_version"], "1")
        self.assertEqual(model.spent_usd, Decimal("0.01"))
        self.assertEqual(len(transport.calls), 1)

    def test_apply_edits_response_conforms_to_client_parser(self):
        invoker = RecordingInvoker(
            {
                "type": "apply_edits",
                "summary": "fix return value",
                "edits": [
                    {
                        "path": "src/app.py",
                        "old_text": "return 1",
                        "new_text": "return 2",
                    }
                ],
            }
        )
        model, _ = self.client(self.service(invoker))
        decision = asyncio.run(model.decide(repair_turn()))
        self.assertIsInstance(decision, ApplyEditsDecision)
        self.assertEqual(decision.edits[0].new_text, "return 2")

    def test_identical_replay_returns_cached_response_without_second_provider_call(self):
        invoker = RecordingInvoker()
        service = self.service(invoker)
        model, transport = self.client(service)
        asyncio.run(model.decide(repair_turn()))
        assert transport.last_body is not None

        replay = asyncio.run(service.handle(body=transport.last_body, auth=now_auth()))

        self.assertEqual(replay.status_code, 200)
        self.assertEqual(len(invoker.calls), 1)

    def test_same_idempotency_key_with_different_budget_conflicts(self):
        invoker = RecordingInvoker()
        service = self.service(invoker)
        model, transport = self.client(service)
        asyncio.run(model.decide(repair_turn()))
        assert transport.last_body is not None
        payload = json.loads(transport.last_body)
        payload["budget"]["max_cost_usd"] = "0.10"
        conflicting = json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")

        with self.assertRaises(ProviderBrokerIdempotencyConflict):
            asyncio.run(service.handle(body=conflicting, auth=now_auth()))
        self.assertEqual(len(invoker.calls), 1)

    def test_request_id_is_recomputed_server_side(self):
        service = self.service()
        model, transport = self.client(service)
        asyncio.run(model.decide(repair_turn()))
        assert transport.last_body is not None
        payload = json.loads(transport.last_body)
        payload["request_id"] = "sha256:" + "0" * 64
        payload["idempotency_key"] = payload["request_id"]
        tampered = json.dumps(payload).encode()

        with self.assertRaises(ProviderBrokerRequestError):
            asyncio.run(service.handle(body=tampered, auth=now_auth()))

    def test_extra_request_field_fails_schema_before_provider(self):
        invoker = RecordingInvoker()
        service = self.service(invoker)
        model, transport = self.client(service)
        asyncio.run(model.decide(repair_turn()))
        assert transport.last_body is not None
        payload = json.loads(transport.last_body)
        payload["provider_api_key"] = "should-never-be-accepted"

        with self.assertRaises(ProviderBrokerRequestError):
            asyncio.run(service.handle(body=json.dumps(payload).encode(), auth=now_auth()))
        self.assertEqual(len(invoker.calls), 1)

    def test_wrong_subject_is_rejected_before_provider(self):
        invoker = RecordingInvoker()
        service = self.service(invoker)
        model, transport = self.client(service)
        asyncio.run(model.decide(repair_turn()))
        assert transport.last_body is not None

        with self.assertRaises(ProviderBrokerAuthenticationError):
            asyncio.run(
                service.handle(
                    body=transport.last_body,
                    auth=now_auth(subject="unknown_service"),
                )
            )
        self.assertEqual(len(invoker.calls), 1)

    def test_wrong_audience_and_expired_auth_are_rejected(self):
        service = self.service()
        model, transport = self.client(service)
        asyncio.run(model.decide(repair_turn()))
        assert transport.last_body is not None
        now = datetime.now(timezone.utc)

        with self.assertRaises(ProviderBrokerAuthenticationError):
            asyncio.run(
                service.handle(
                    body=transport.last_body,
                    auth=now_auth(audience="api.openai.com"),
                )
            )
        with self.assertRaises(ProviderBrokerAuthenticationError):
            asyncio.run(
                service.handle(
                    body=transport.last_body,
                    auth=now_auth(
                        issued_at=now - timedelta(minutes=10),
                        expires_at=now - timedelta(minutes=5),
                    ),
                )
            )

    def test_caller_cost_grant_above_server_ceiling_fails(self):
        invoker = RecordingInvoker()
        service = self.service(
            invoker,
            policy=BrokerServicePolicy(max_cost_usd_per_request=Decimal("0.05")),
        )
        model, _ = self.client(service)
        with self.assertRaises(ProviderBrokerRequestError):
            asyncio.run(model.decide(repair_turn()))
        self.assertEqual(invoker.calls, [])

    def test_provider_cannot_report_cost_above_caller_grant(self):
        invoker = RecordingInvoker(cost=Decimal("0.21"))
        model, _ = self.client(self.service(invoker))
        with self.assertRaises(ProviderBrokerInvocationError):
            asyncio.run(model.decide(repair_turn()))
        self.assertEqual(len(invoker.calls), 1)

    def test_invalid_provider_decision_is_rejected_by_response_schema(self):
        invoker = RecordingInvoker({"type": "launch_missiles", "target": "nope"})
        model, _ = self.client(self.service(invoker))
        with self.assertRaises(ProviderBrokerInvocationError):
            asyncio.run(model.decide(repair_turn()))

    def test_unresolvable_selector_fails_before_provider_invocation(self):
        invoker = RecordingInvoker()
        empty = StaticProviderSelectorResolver(())
        model, _ = self.client(self.service(invoker, selector=empty))
        with self.assertRaises(ProviderBrokerInvocationError):
            asyncio.run(model.decide(repair_turn()))
        self.assertEqual(invoker.calls, [])

    def test_resolved_provider_family_must_match_binding(self):
        invoker = RecordingInvoker()

        class WrongFamilyResolver:
            def resolve(self, **kwargs):
                return ResolvedProviderTarget(
                    provider_family="anthropic",
                    model_id="mock-model",
                    selector_version="v1",
                )

        model, _ = self.client(self.service(invoker, selector=WrongFamilyResolver()))
        with self.assertRaises(ProviderBrokerInvocationError):
            asyncio.run(model.decide(repair_turn()))
        self.assertEqual(invoker.calls, [])

    def test_provider_timeout_is_enforced_server_side(self):
        service = self.service(
            SlowInvoker(),
            policy=BrokerServicePolicy(provider_timeout_seconds=1),
        )
        # Use a deliberately slower implementation without making the test itself slow.
        async def very_slow(**kwargs):
            await asyncio.sleep(2)
            return ProviderInvocationResult(
                decision={"type": "read_files", "paths": ["src/app.py"]},
                input_tokens=1,
                output_tokens=1,
                cost_usd=Decimal("0.01"),
            )
        service.provider_invoker.invoke = very_slow  # type: ignore[method-assign]
        model, _ = self.client(service)
        with self.assertRaises(ProviderBrokerInvocationError):
            asyncio.run(model.decide(repair_turn()))

    def test_request_and_response_schema_files_are_draft_2020_12(self):
        for relative in (
            "factory/schemas/provider-broker-repair-request.schema.json",
            "factory/schemas/provider-broker-repair-response.schema.json",
        ):
            parsed = json.loads((self.root / relative).read_text(encoding="utf-8"))
            self.assertEqual(parsed["$schema"], "https://json-schema.org/draft/2020-12/schema")
            self.assertFalse(parsed.get("additionalProperties", True))

    def test_service_policy_bounds(self):
        with self.assertRaises(ValueError):
            BrokerServicePolicy(allowed_subjects=())
        with self.assertRaises(ValueError):
            BrokerServicePolicy(max_cost_usd_per_request=Decimal("0"))
        with self.assertRaises(ValueError):
            BrokerServicePolicy(provider_timeout_seconds=0)


if __name__ == "__main__":
    unittest.main()
