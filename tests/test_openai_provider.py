from __future__ import annotations

import asyncio
import json
import sys
import unittest
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from factory_runtime.openai_provider import (  # noqa: E402
    OpenAIProviderCredentialError,
    OpenAIProviderDisabledError,
    OpenAIProviderPolicy,
    OpenAIProviderPricingError,
    OpenAIProviderProtocolError,
    OpenAIResponsesProviderInvoker,
    ProviderCredentialLease,
    ProviderHTTPResponse,
    ProviderPricingQuote,
)
from factory_runtime.provider_broker_service import ResolvedProviderTarget  # noqa: E402


MODEL = "gpt-5.6-sol"
TARGET = ResolvedProviderTarget(
    provider_family="openai",
    model_id=MODEL,
    selector_version="test-v1",
)


class CountingCredentialSource:
    def __init__(self, *, ttl_seconds: int = 300) -> None:
        self.calls = 0
        self.ttl_seconds = ttl_seconds

    async def issue(self, *, target: ResolvedProviderTarget) -> ProviderCredentialLease:
        self.calls += 1
        now = datetime.now(timezone.utc)
        return ProviderCredentialLease(
            token="provider-test-secret-1234567890",
            provider_family=target.provider_family,
            audience="api.openai.com",
            issued_at=now - timedelta(seconds=1),
            expires_at=now + timedelta(seconds=self.ttl_seconds),
        )


class StaticPricingSource:
    def __init__(
        self,
        *,
        input_price: Decimal = Decimal("4"),
        output_price: Decimal = Decimal("20"),
        effective_delta: timedelta = timedelta(minutes=-5),
        expires_delta: timedelta = timedelta(hours=1),
    ) -> None:
        self.calls = 0
        self.input_price = input_price
        self.output_price = output_price
        self.effective_delta = effective_delta
        self.expires_delta = expires_delta

    async def quote(self, *, target: ResolvedProviderTarget) -> ProviderPricingQuote:
        self.calls += 1
        now = datetime.now(timezone.utc)
        return ProviderPricingQuote(
            model_id=target.model_id,
            input_usd_per_million_tokens=self.input_price,
            output_usd_per_million_tokens=self.output_price,
            effective_at=now + self.effective_delta,
            expires_at=now + self.expires_delta,
            source_id="test-pricing-v1",
        )


class RecordingTransport:
    def __init__(self, response: ProviderHTTPResponse) -> None:
        self.response = response
        self.calls = 0
        self.last_endpoint = None
        self.last_headers = None
        self.last_body = None

    async def post_json(self, *, endpoint, headers, body, timeout_seconds):
        self.calls += 1
        self.last_endpoint = endpoint
        self.last_headers = dict(headers)
        self.last_body = body
        self.last_timeout = timeout_seconds
        return self.response


def provider_payload(decision: dict, *, model: str = MODEL, input_tokens: int = 1000, output_tokens: int = 100):
    return {
        "id": "resp_test",
        "object": "response",
        "status": "completed",
        "model": model,
        "error": None,
        "incomplete_details": None,
        "output": [
            {
                "type": "message",
                "role": "assistant",
                "content": [
                    {
                        "type": "output_text",
                        "text": json.dumps(decision, separators=(",", ":")),
                        "annotations": [],
                    }
                ],
            }
        ],
        "usage": {
            "input_tokens": input_tokens,
            "output_tokens": output_tokens,
            "total_tokens": input_tokens + output_tokens,
            "output_tokens_details": {"reasoning_tokens": 0},
        },
    }


def read_files_decision():
    return {
        "type": "read_files",
        "paths": ["app.py"],
        "summary": "",
        "edits": [],
        "reason": "",
    }


def make_invoker(
    response: ProviderHTTPResponse,
    *,
    live_enabled: bool,
    max_output_tokens: int = 512,
    credential_source=None,
    pricing_source=None,
):
    credentials = credential_source or CountingCredentialSource()
    pricing = pricing_source or StaticPricingSource()
    transport = RecordingTransport(response)
    invoker = OpenAIResponsesProviderInvoker(
        credentials,
        pricing,
        transport,
        policy=OpenAIProviderPolicy(
            live_enabled=live_enabled,
            max_output_tokens=max_output_tokens,
            reasoning_effort="high",
        ),
    )
    return invoker, credentials, pricing, transport


class OpenAIProviderTests(unittest.TestCase):
    def test_disabled_policy_fails_before_pricing_credentials_or_transport(self):
        response = ProviderHTTPResponse(
            status_code=200,
            body=json.dumps(provider_payload(read_files_decision())).encode(),
        )
        invoker, credentials, pricing, transport = make_invoker(response, live_enabled=False)
        with self.assertRaises(OpenAIProviderDisabledError):
            asyncio.run(
                invoker.invoke(
                    target=TARGET,
                    turn={"repair_id": "r1"},
                    max_cost_usd=Decimal("0.10"),
                    decision_schema_version="1",
                )
            )
        self.assertEqual(pricing.calls, 0)
        self.assertEqual(credentials.calls, 0)
        self.assertEqual(transport.calls, 0)
        self.assertEqual(invoker.invocation_count, 0)

    def test_live_capable_path_builds_strict_responses_request_and_normalizes_decision(self):
        response = ProviderHTTPResponse(
            status_code=200,
            body=json.dumps(provider_payload(read_files_decision())).encode(),
        )
        invoker, credentials, pricing, transport = make_invoker(response, live_enabled=True)
        result = asyncio.run(
            invoker.invoke(
                target=TARGET,
                turn={"repair_id": "r1", "inventory": ["app.py"]},
                max_cost_usd=Decimal("0.10"),
                decision_schema_version="1",
            )
        )
        self.assertEqual(result.decision, {"type": "read_files", "paths": ["app.py"]})
        self.assertEqual(result.input_tokens, 1000)
        self.assertEqual(result.output_tokens, 100)
        self.assertEqual(result.cost_usd, Decimal("0.00600000"))
        self.assertEqual(invoker.invocation_count, 1)
        self.assertEqual(credentials.calls, 1)
        self.assertEqual(pricing.calls, 1)
        self.assertEqual(transport.calls, 1)
        self.assertEqual(transport.last_endpoint, "https://api.openai.com/v1/responses")
        self.assertTrue(transport.last_headers["Authorization"].startswith("Bearer "))

        request = json.loads(transport.last_body.decode())
        self.assertEqual(request["model"], MODEL)
        self.assertIs(request["store"], False)
        self.assertNotIn("tools", request)
        self.assertEqual(request["reasoning"], {"effort": "high"})
        self.assertEqual(request["text"]["format"]["type"], "json_schema")
        self.assertIs(request["text"]["format"]["strict"], True)
        self.assertNotIn("provider-test-secret", transport.last_body.decode())

    def test_stale_pricing_fails_before_credentials_or_transport(self):
        response = ProviderHTTPResponse(200, b"{}")
        stale = StaticPricingSource(
            effective_delta=timedelta(days=-2),
            expires_delta=timedelta(hours=1),
        )
        invoker, credentials, pricing, transport = make_invoker(
            response,
            live_enabled=True,
            pricing_source=stale,
        )
        with self.assertRaises(OpenAIProviderPricingError):
            asyncio.run(
                invoker.invoke(
                    target=TARGET,
                    turn={"repair_id": "r1"},
                    max_cost_usd=Decimal("0.10"),
                    decision_schema_version="1",
                )
            )
        self.assertEqual(pricing.calls, 1)
        self.assertEqual(credentials.calls, 0)
        self.assertEqual(transport.calls, 0)

    def test_worst_case_cost_exposure_fails_before_credentials(self):
        response = ProviderHTTPResponse(200, b"{}")
        invoker, credentials, pricing, transport = make_invoker(
            response,
            live_enabled=True,
            max_output_tokens=4096,
        )
        with self.assertRaises(OpenAIProviderPricingError):
            asyncio.run(
                invoker.invoke(
                    target=TARGET,
                    turn={"repair_id": "r1", "payload": "x" * 5000},
                    max_cost_usd=Decimal("0.01"),
                    decision_schema_version="1",
                )
            )
        self.assertEqual(pricing.calls, 1)
        self.assertEqual(credentials.calls, 0)
        self.assertEqual(transport.calls, 0)

    def test_overlong_credential_lease_fails_before_transport(self):
        response = ProviderHTTPResponse(200, b"{}")
        credentials = CountingCredentialSource(ttl_seconds=1800)
        invoker, credentials, _, transport = make_invoker(
            response,
            live_enabled=True,
            credential_source=credentials,
        )
        with self.assertRaises(OpenAIProviderCredentialError):
            asyncio.run(
                invoker.invoke(
                    target=TARGET,
                    turn={"repair_id": "r1"},
                    max_cost_usd=Decimal("0.10"),
                    decision_schema_version="1",
                )
            )
        self.assertEqual(credentials.calls, 1)
        self.assertEqual(transport.calls, 0)

    def test_non_200_response_is_not_retried(self):
        response = ProviderHTTPResponse(429, b'{"error":{"message":"rate limited"}}')
        invoker, credentials, _, transport = make_invoker(response, live_enabled=True)
        with self.assertRaises(OpenAIProviderProtocolError):
            asyncio.run(
                invoker.invoke(
                    target=TARGET,
                    turn={"repair_id": "r1"},
                    max_cost_usd=Decimal("0.10"),
                    decision_schema_version="1",
                )
            )
        self.assertEqual(credentials.calls, 1)
        self.assertEqual(transport.calls, 1)
        self.assertEqual(invoker.invocation_count, 0)

    def test_response_model_mismatch_fails_closed(self):
        response = ProviderHTTPResponse(
            200,
            json.dumps(provider_payload(read_files_decision(), model="different-model")).encode(),
        )
        invoker, _, _, _ = make_invoker(response, live_enabled=True)
        with self.assertRaises(OpenAIProviderProtocolError):
            asyncio.run(
                invoker.invoke(
                    target=TARGET,
                    turn={"repair_id": "r1"},
                    max_cost_usd=Decimal("0.10"),
                    decision_schema_version="1",
                )
            )

    def test_refusal_fails_closed(self):
        payload = provider_payload(read_files_decision())
        payload["output"][0]["content"] = [{"type": "refusal", "refusal": "no"}]
        response = ProviderHTTPResponse(200, json.dumps(payload).encode())
        invoker, _, _, _ = make_invoker(response, live_enabled=True)
        with self.assertRaises(OpenAIProviderProtocolError):
            asyncio.run(
                invoker.invoke(
                    target=TARGET,
                    turn={"repair_id": "r1"},
                    max_cost_usd=Decimal("0.10"),
                    decision_schema_version="1",
                )
            )

    def test_contradictory_structured_decision_fails_closed(self):
        bad = read_files_decision()
        bad["summary"] = "should be empty"
        response = ProviderHTTPResponse(200, json.dumps(provider_payload(bad)).encode())
        invoker, _, _, _ = make_invoker(response, live_enabled=True)
        with self.assertRaises(OpenAIProviderProtocolError):
            asyncio.run(
                invoker.invoke(
                    target=TARGET,
                    turn={"repair_id": "r1"},
                    max_cost_usd=Decimal("0.10"),
                    decision_schema_version="1",
                )
            )

    def test_reported_usage_over_budget_fails_closed(self):
        response = ProviderHTTPResponse(
            200,
            json.dumps(
                provider_payload(
                    read_files_decision(),
                    input_tokens=10000,
                    output_tokens=10000,
                )
            ).encode(),
        )
        invoker, _, _, _ = make_invoker(response, live_enabled=True, max_output_tokens=64)
        with self.assertRaises(OpenAIProviderPricingError):
            asyncio.run(
                invoker.invoke(
                    target=TARGET,
                    turn={"repair_id": "r1"},
                    max_cost_usd=Decimal("0.10"),
                    decision_schema_version="1",
                )
            )

    def test_policy_rejects_endpoint_drift(self):
        with self.assertRaises(ValueError):
            OpenAIProviderPolicy(endpoint="https://example.com/v1/responses")


if __name__ == "__main__":
    unittest.main()
