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
    BrokerHTTPResponse,
    EphemeralBrokerCredential,
    ProviderBrokerBudget,
    ProviderBrokerBudgetError,
    ProviderBrokerConfigError,
    ProviderBrokerCredentialError,
    ProviderBrokerProtocolError,
    ProviderBrokerRepairModel,
    load_provider_broker_binding,
)
from factory_runtime.structured_repair import (  # noqa: E402
    ApplyEditsDecision,
    EscalateDecision,
    ReadFilesDecision,
    RepairFileContext,
    RepairModelTurn,
)


class FakeCredentialSource:
    def __init__(
        self,
        *,
        audience: str = "provider-broker.internal",
        issued_offset_seconds: int = -1,
        ttl_seconds: int = 300,
        token: str = "factory-broker-ephemeral-token-123456",
    ) -> None:
        self.audience = audience
        self.issued_offset_seconds = issued_offset_seconds
        self.ttl_seconds = ttl_seconds
        self.token = token
        self.calls = 0

    async def issue(self, *, audience: str) -> EphemeralBrokerCredential:
        self.calls += 1
        now = datetime.now(timezone.utc)
        issued_at = now + timedelta(seconds=self.issued_offset_seconds)
        return EphemeralBrokerCredential(
            token=self.token,
            audience=self.audience,
            issued_at=issued_at,
            expires_at=issued_at + timedelta(seconds=self.ttl_seconds),
        )


class FakeTransport:
    def __init__(self, decision: dict, *, cost: str = "0.01", status: int = 200) -> None:
        self.decision = decision
        self.cost = cost
        self.status = status
        self.calls: list[dict] = []

    async def post_json(self, *, endpoint, headers, body, timeout_seconds):
        payload = json.loads(body.decode("utf-8"))
        self.calls.append(
            {
                "endpoint": endpoint,
                "headers": dict(headers),
                "body": body,
                "payload": payload,
                "timeout_seconds": timeout_seconds,
            }
        )
        response = {
            "protocol_version": "factory-repair-broker-v1",
            "request_id": payload["request_id"],
            "binding_digest": payload["binding_digest"],
            "provider_profile": payload["provider_profile"],
            "provider_family": payload["provider_family"],
            "model_selector": payload["model_selector"],
            "decision": self.decision,
            "usage": {
                "input_tokens": 120,
                "output_tokens": 35,
                "cost_usd": self.cost,
            },
        }
        return BrokerHTTPResponse(
            status_code=self.status,
            body=json.dumps(response, separators=(",", ":")).encode("utf-8"),
        )


class TamperingTransport(FakeTransport):
    def __init__(self, field: str, value, **kwargs) -> None:
        super().__init__({"type": "escalate", "reason": "test"}, **kwargs)
        self.field = field
        self.value = value

    async def post_json(self, *, endpoint, headers, body, timeout_seconds):
        payload = json.loads(body.decode("utf-8"))
        self.calls.append(
            {
                "endpoint": endpoint,
                "headers": dict(headers),
                "body": body,
                "payload": payload,
                "timeout_seconds": timeout_seconds,
            }
        )
        response = {
            "protocol_version": "factory-repair-broker-v1",
            "request_id": payload["request_id"],
            "binding_digest": payload["binding_digest"],
            "provider_profile": payload["provider_profile"],
            "provider_family": payload["provider_family"],
            "model_selector": payload["model_selector"],
            "decision": {"type": "escalate", "reason": "test"},
            "usage": {"input_tokens": 1, "output_tokens": 1, "cost_usd": "0.01"},
        }
        response[self.field] = self.value
        return BrokerHTTPResponse(status_code=200, body=json.dumps(response).encode())


def make_turn(*, large: bool = False) -> RepairModelTurn:
    suffix = "x" * 5000 if large else ""
    return RepairModelTurn(
        repair_id="repair-1",
        attempt_number=1,
        turn_number=1,
        original_command=("python", "-m", "unittest", "discover", "-s", "tests"),
        stdout_excerpt="1 failed" + suffix,
        stderr_excerpt="AssertionError" + suffix,
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


def default_budget(**overrides) -> ProviderBrokerBudget:
    values = {
        "max_cost_usd_per_call": Decimal("0.20"),
        "max_total_cost_usd": Decimal("0.50"),
        "max_request_bytes": 256 * 1024,
        "max_response_bytes": 64 * 1024,
        "timeout_seconds": 60,
        "max_credential_ttl_seconds": 900,
    }
    values.update(overrides)
    return ProviderBrokerBudget(**values)


def write_minimal_registry(root: Path, *, network_allow: list[str] | None = None) -> None:
    (root / "factory" / "roles").mkdir(parents=True)
    (root / "factory" / "profiles").mkdir(parents=True)
    (root / "factory" / "roles" / "engineering_agent.yaml").write_text(
        """schema_version: '1.0'\nrole_id: engineering_agent\nprovider_profile: coding_primary\nnetwork_policy: provider_restricted\nsecret_policy: brokered_ephemeral_only\n""",
        encoding="utf-8",
    )
    (root / "factory" / "profiles" / "providers.yaml").write_text(
        """schema_version: '1.0'\nprofiles:\n  coding_primary:\n    workload: coding\n    provider_family: openai\n    model_selector: FACTORY_CODING_MODEL\n    authority_effect: none\n""",
        encoding="utf-8",
    )
    allow = network_allow or ["provider-broker.internal:443"]
    (root / "factory" / "profiles" / "networks.yaml").write_text(
        "schema_version: '1.0'\ndefault: deny\nprofiles:\n  provider_restricted:\n    allow:\n"
        + "".join(f"      - {item}\n" for item in allow),
        encoding="utf-8",
    )
    (root / "factory" / "profiles" / "credentials.yaml").write_text(
        """schema_version: '1.0'\ndefault: deny\nprofiles:\n  controller_service:\n    identity_type: workload_oidc\n    secrets: [provider_broker_token]\n""",
        encoding="utf-8",
    )


class ProviderBrokerBindingTests(unittest.TestCase):
    def test_live_factory_registry_binds_expected_repair_provider_path(self):
        root = Path(__file__).resolve().parents[1]
        binding = load_provider_broker_binding(root)
        self.assertEqual(binding.role_id, "engineering_agent")
        self.assertEqual(binding.provider_profile, "coding_primary")
        self.assertEqual(binding.provider_family, "openai")
        self.assertEqual(binding.model_selector, "FACTORY_CODING_MODEL")
        self.assertEqual(binding.network_policy, "provider_restricted")
        self.assertEqual(
            binding.endpoint,
            "https://provider-broker.internal/v1/repair/decide",
        )
        self.assertTrue(binding.binding_digest.startswith("sha256:"))

    def test_direct_provider_endpoint_is_rejected(self):
        root = Path(__file__).resolve().parents[1]
        with self.assertRaises(ProviderBrokerConfigError):
            load_provider_broker_binding(
                root,
                endpoint="https://api.openai.com/v1/responses",
            )

    def test_network_policy_with_direct_provider_access_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            write_minimal_registry(
                root,
                network_allow=[
                    "provider-broker.internal:443",
                    "api.openai.com:443",
                ],
            )
            with self.assertRaises(ProviderBrokerConfigError):
                load_provider_broker_binding(root)

    def test_missing_broker_token_issuance_path_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            write_minimal_registry(root)
            (root / "factory" / "profiles" / "credentials.yaml").write_text(
                """schema_version: '1.0'\ndefault: deny\nprofiles:\n  controller_service:\n    identity_type: workload_oidc\n    secrets: []\n""",
                encoding="utf-8",
            )
            with self.assertRaises(ProviderBrokerConfigError):
                load_provider_broker_binding(root)

    def test_authority_effect_must_remain_none(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            write_minimal_registry(root)
            (root / "factory" / "profiles" / "providers.yaml").write_text(
                """schema_version: '1.0'\nprofiles:\n  coding_primary:\n    provider_family: openai\n    model_selector: FACTORY_CODING_MODEL\n    authority_effect: approve\n""",
                encoding="utf-8",
            )
            with self.assertRaises(ProviderBrokerConfigError):
                load_provider_broker_binding(root)


class ProviderBrokerRepairModelTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.binding = load_provider_broker_binding(Path(__file__).resolve().parents[1])

    def model(self, transport, *, credential_source=None, budget=None):
        return ProviderBrokerRepairModel(
            self.binding,
            credential_source or FakeCredentialSource(),
            transport,
            budget or default_budget(),
        )

    def test_read_files_decision_happy_path_and_request_binding(self):
        transport = FakeTransport({"type": "read_files", "paths": ["src/app.py"]})
        model = self.model(transport)
        decision = asyncio.run(model.decide(make_turn()))

        self.assertIsInstance(decision, ReadFilesDecision)
        self.assertEqual(decision.paths, ("src/app.py",))
        self.assertEqual(model.spent_usd, Decimal("0.01"))
        self.assertEqual(len(model.call_records), 1)
        self.assertEqual(len(transport.calls), 1)
        call = transport.calls[0]
        payload = call["payload"]
        self.assertEqual(call["endpoint"], self.binding.endpoint)
        self.assertEqual(call["timeout_seconds"], 60)
        self.assertEqual(payload["role_id"], "engineering_agent")
        self.assertEqual(payload["provider_profile"], "coding_primary")
        self.assertEqual(payload["provider_family"], "openai")
        self.assertEqual(payload["model_selector"], "FACTORY_CODING_MODEL")
        self.assertEqual(payload["budget"]["max_cost_usd"], "0.20")
        self.assertEqual(payload["request_id"], payload["idempotency_key"])
        self.assertEqual(call["headers"]["Idempotency-Key"], payload["request_id"])
        self.assertEqual(
            call["headers"]["X-Factory-Binding-Digest"],
            self.binding.binding_digest,
        )
        self.assertTrue(call["headers"]["Authorization"].startswith("Bearer factory-broker-"))
        self.assertNotIn("factory-broker-ephemeral-token", call["body"].decode("utf-8"))

    def test_apply_edits_decision_parses_strictly(self):
        transport = FakeTransport(
            {
                "type": "apply_edits",
                "summary": "fix off-by-one",
                "edits": [
                    {
                        "path": "src/app.py",
                        "old_text": "return 1",
                        "new_text": "return 2",
                    }
                ],
            }
        )
        decision = asyncio.run(self.model(transport).decide(make_turn()))
        self.assertIsInstance(decision, ApplyEditsDecision)
        self.assertEqual(decision.summary, "fix off-by-one")
        self.assertEqual(decision.edits[0].path, "src/app.py")

    def test_escalate_decision_parses(self):
        decision = asyncio.run(
            self.model(FakeTransport({"type": "escalate", "reason": "ambiguous failure"})).decide(
                make_turn()
            )
        )
        self.assertIsInstance(decision, EscalateDecision)
        self.assertEqual(decision.reason, "ambiguous failure")

    def test_request_binding_mismatch_fails_closed(self):
        transport = TamperingTransport("request_id", "sha256:" + "0" * 64)
        with self.assertRaises(ProviderBrokerProtocolError):
            asyncio.run(self.model(transport).decide(make_turn()))

    def test_unknown_top_level_response_key_fails_closed(self):
        class ExtraKeyTransport(FakeTransport):
            async def post_json(self, *, endpoint, headers, body, timeout_seconds):
                base = await super().post_json(
                    endpoint=endpoint,
                    headers=headers,
                    body=body,
                    timeout_seconds=timeout_seconds,
                )
                payload = json.loads(base.body)
                payload["surprise"] = "ignored?"
                return BrokerHTTPResponse(status_code=200, body=json.dumps(payload).encode())

        with self.assertRaises(ProviderBrokerProtocolError):
            asyncio.run(
                self.model(ExtraKeyTransport({"type": "escalate", "reason": "x"})).decide(
                    make_turn()
                )
            )

    def test_http_error_is_not_automatically_retried(self):
        transport = FakeTransport({"type": "escalate", "reason": "x"}, status=429)
        with self.assertRaises(ProviderBrokerProtocolError):
            asyncio.run(self.model(transport).decide(make_turn()))
        self.assertEqual(len(transport.calls), 1)

    def test_wrong_audience_credential_fails_before_transport(self):
        transport = FakeTransport({"type": "escalate", "reason": "x"})
        model = self.model(
            transport,
            credential_source=FakeCredentialSource(audience="api.openai.com"),
        )
        with self.assertRaises(ProviderBrokerCredentialError):
            asyncio.run(model.decide(make_turn()))
        self.assertEqual(transport.calls, [])

    def test_expired_credential_fails_before_transport(self):
        transport = FakeTransport({"type": "escalate", "reason": "x"})
        model = self.model(
            transport,
            credential_source=FakeCredentialSource(
                issued_offset_seconds=-600,
                ttl_seconds=300,
            ),
        )
        with self.assertRaises(ProviderBrokerCredentialError):
            asyncio.run(model.decide(make_turn()))
        self.assertEqual(transport.calls, [])

    def test_credential_ttl_above_ephemeral_limit_fails(self):
        transport = FakeTransport({"type": "escalate", "reason": "x"})
        model = self.model(
            transport,
            credential_source=FakeCredentialSource(ttl_seconds=1800),
        )
        with self.assertRaises(ProviderBrokerCredentialError):
            asyncio.run(model.decide(make_turn()))

    def test_reported_cost_above_grant_fails_closed(self):
        transport = FakeTransport({"type": "escalate", "reason": "x"}, cost="0.21")
        model = self.model(transport)
        with self.assertRaises(ProviderBrokerBudgetError):
            asyncio.run(model.decide(make_turn()))
        self.assertEqual(model.spent_usd, Decimal("0"))
        self.assertEqual(model.call_records, ())

    def test_remaining_budget_is_sent_and_then_exhausts(self):
        transport = FakeTransport({"type": "escalate", "reason": "x"}, cost="0.20")
        model = self.model(
            transport,
            budget=default_budget(
                max_cost_usd_per_call=Decimal("0.20"),
                max_total_cost_usd=Decimal("0.30"),
            ),
        )
        asyncio.run(model.decide(make_turn()))
        transport.cost = "0.10"
        asyncio.run(model.decide(make_turn()))
        self.assertEqual(transport.calls[1]["payload"]["budget"]["max_cost_usd"], "0.10")
        self.assertEqual(model.spent_usd, Decimal("0.30"))
        call_count = len(transport.calls)
        with self.assertRaises(ProviderBrokerBudgetError):
            asyncio.run(model.decide(make_turn()))
        self.assertEqual(len(transport.calls), call_count)

    def test_request_size_cap_fails_before_credential_or_transport(self):
        transport = FakeTransport({"type": "escalate", "reason": "x"})
        credential = FakeCredentialSource()
        model = self.model(
            transport,
            credential_source=credential,
            budget=default_budget(max_request_bytes=1024),
        )
        with self.assertRaises(ProviderBrokerProtocolError):
            asyncio.run(model.decide(make_turn(large=True)))
        self.assertEqual(credential.calls, 0)
        self.assertEqual(transport.calls, [])

    def test_response_size_cap_fails_closed(self):
        class HugeTransport(FakeTransport):
            async def post_json(self, *, endpoint, headers, body, timeout_seconds):
                return BrokerHTTPResponse(status_code=200, body=b"x" * 2048)

        model = self.model(
            HugeTransport({"type": "escalate", "reason": "x"}),
            budget=default_budget(max_response_bytes=1024),
        )
        with self.assertRaises(ProviderBrokerProtocolError):
            asyncio.run(model.decide(make_turn()))

    def test_budget_requires_decimal_and_valid_relationship(self):
        with self.assertRaises(ProviderBrokerBudgetError):
            ProviderBrokerBudget(
                max_cost_usd_per_call=Decimal("1.00"),
                max_total_cost_usd=Decimal("0.50"),
            )
        with self.assertRaises(ProviderBrokerBudgetError):
            ProviderBrokerBudget(  # type: ignore[arg-type]
                max_cost_usd_per_call=0.1,
                max_total_cost_usd=Decimal("0.50"),
            )


if __name__ == "__main__":
    unittest.main()
