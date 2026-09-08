from __future__ import annotations

import asyncio
import json
import sys
import unittest
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from pathlib import Path
from urllib.parse import urlparse

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from factory_runtime.provider_broker import (  # noqa: E402
    BrokerHTTPResponse,
    EphemeralBrokerCredential,
    ProviderBrokerBudget,
    ProviderBrokerProtocolError,
    ProviderBrokerRepairModel,
    load_provider_broker_binding,
)
from factory_runtime.provider_broker_http import (  # noqa: E402
    BearerTokenAuthenticator,
    BrokerAuthenticatorUnavailable,
    BrokerHTTPApplicationResponse,
    BrokerHTTPRequest,
    BrokerHTTPEdgePolicy,
    BrokerTokenRejected,
    ReferenceProviderBrokerHTTPApplication,
)
from factory_runtime.provider_broker_service import (  # noqa: E402
    BrokerAuthContext,
    ProviderInvocationResult,
    ReferenceProviderBrokerService,
    StaticProviderSelectorResolver,
)
from factory_runtime.structured_repair import ReadFilesDecision, RepairModelTurn  # noqa: E402


RAW_TOKEN = "factory-edge-token-1234567890"


class FakeCredentialSource:
    async def issue(self, *, audience: str) -> EphemeralBrokerCredential:
        now = datetime.now(timezone.utc)
        return EphemeralBrokerCredential(
            token=RAW_TOKEN,
            audience=audience,
            issued_at=now - timedelta(seconds=1),
            expires_at=now + timedelta(minutes=5),
        )


class RecordingAuthenticator(BearerTokenAuthenticator):
    def __init__(self, *, mode: str = "success") -> None:
        self.mode = mode
        self.tokens: list[str] = []

    async def authenticate(self, token: str) -> BrokerAuthContext:
        self.tokens.append(token)
        if self.mode == "reject":
            raise BrokerTokenRejected("invalid")
        if self.mode == "unavailable":
            raise BrokerAuthenticatorUnavailable("down")
        if self.mode == "slow":
            await asyncio.sleep(2)
        now = datetime.now(timezone.utc)
        return BrokerAuthContext(
            subject="engineering_agent_service",
            audience="provider-broker.internal",
            issued_at=now - timedelta(seconds=1),
            expires_at=now + timedelta(minutes=5),
        )


class RecordingInvoker:
    def __init__(self, *, invalid: bool = False) -> None:
        self.invalid = invalid
        self.calls = 0

    async def invoke(self, *, target, turn, max_cost_usd, decision_schema_version):
        self.calls += 1
        decision = (
            {"type": "not_allowed", "payload": "x"}
            if self.invalid
            else {"type": "read_files", "paths": ["src/app.py"]}
        )
        return ProviderInvocationResult(
            decision=decision,
            input_tokens=12,
            output_tokens=5,
            cost_usd=Decimal("0.01"),
        )


class ApplicationTransport:
    """BrokerTransport implementation over the reference HTTP application."""

    def __init__(self, application: ReferenceProviderBrokerHTTPApplication) -> None:
        self.application = application
        self.responses: list[BrokerHTTPApplicationResponse] = []

    async def post_json(self, *, endpoint, headers, body, timeout_seconds):
        parsed = urlparse(endpoint)
        response = await self.application.handle(
            BrokerHTTPRequest(
                method="POST",
                path=parsed.path,
                headers=tuple(headers.items()),
                body=body,
            )
        )
        self.responses.append(response)
        return BrokerHTTPResponse(status_code=response.status_code, body=response.body)


def turn() -> RepairModelTurn:
    return RepairModelTurn(
        repair_id="repair-http-1",
        attempt_number=1,
        turn_number=1,
        original_command=("python", "-m", "pytest", "-q"),
        stdout_excerpt="1 failed",
        stderr_excerpt="AssertionError",
        diagnostic_redaction_count=0,
        inventory=("src/app.py",),
        files=(),
    )


def json_headers(*, authorization: str = f"Bearer {RAW_TOKEN}") -> tuple[tuple[str, str], ...]:
    return (
        ("Authorization", authorization),
        ("Content-Type", "application/json"),
        ("Accept", "application/json"),
    )


class ProviderBrokerHTTPEdgeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.root = Path(__file__).resolve().parents[1]
        cls.binding = load_provider_broker_binding(cls.root)

    def application(self, authenticator=None, *, invoker=None, policy=None):
        provider = invoker or RecordingInvoker()
        service = ReferenceProviderBrokerService(
            self.root,
            self.binding,
            StaticProviderSelectorResolver(
                (
                    (
                        "coding_primary",
                        "openai",
                        "FACTORY_CODING_MODEL",
                        "mock-model-v1",
                        "selector-v1",
                    ),
                )
            ),
            provider,
        )
        auth = authenticator or RecordingAuthenticator()
        return (
            ReferenceProviderBrokerHTTPApplication(service, auth, policy=policy),
            auth,
            provider,
        )

    def test_existing_client_conforms_through_http_edge_and_service(self):
        app, auth, invoker = self.application()
        transport = ApplicationTransport(app)
        model = ProviderBrokerRepairModel(
            self.binding,
            FakeCredentialSource(),
            transport,
            ProviderBrokerBudget(
                max_cost_usd_per_call=Decimal("0.10"),
                max_total_cost_usd=Decimal("0.20"),
            ),
        )

        decision = asyncio.run(model.decide(turn()))

        self.assertIsInstance(decision, ReadFilesDecision)
        self.assertEqual(decision.paths, ("src/app.py",))
        self.assertEqual(auth.tokens, [RAW_TOKEN])
        self.assertEqual(invoker.calls, 1)
        self.assertEqual(model.spent_usd, Decimal("0.01"))
        self.assertEqual(transport.responses[0].status_code, 200)
        headers = dict(transport.responses[0].headers)
        self.assertEqual(headers["Cache-Control"], "no-store")
        self.assertEqual(headers["X-Content-Type-Options"], "nosniff")

    def test_wrong_method_and_path_fail_before_authentication(self):
        app, auth, invoker = self.application()
        for request, expected_status in (
            (BrokerHTTPRequest("GET", "/v1/repair/decide", json_headers(), b"{}"), 405),
            (BrokerHTTPRequest("POST", "/v1/other", json_headers(), b"{}"), 404),
            (BrokerHTTPRequest("POST", "/v1/repair/decide?x=1", json_headers(), b"{}"), 404),
        ):
            response = asyncio.run(app.handle(request))
            self.assertEqual(response.status_code, expected_status)
        self.assertEqual(auth.tokens, [])
        self.assertEqual(invoker.calls, 0)

    def test_duplicate_authorization_is_rejected_before_authenticator(self):
        app, auth, _ = self.application()
        request = BrokerHTTPRequest(
            "POST",
            "/v1/repair/decide",
            json_headers() + (("authorization", f"Bearer {RAW_TOKEN}"),),
            b"{}",
        )
        response = asyncio.run(app.handle(request))
        self.assertEqual(response.status_code, 400)
        self.assertEqual(json.loads(response.body)["error"]["code"], "invalid_request")
        self.assertEqual(auth.tokens, [])

    def test_invalid_bearer_scheme_is_unauthorized(self):
        app, auth, _ = self.application()
        response = asyncio.run(
            app.handle(
                BrokerHTTPRequest(
                    "POST",
                    "/v1/repair/decide",
                    json_headers(authorization="Basic abcdefghijklmnop"),
                    b"{}",
                )
            )
        )
        self.assertEqual(response.status_code, 401)
        self.assertEqual(auth.tokens, [])

    def test_authenticator_rejection_and_unavailability_are_sanitized(self):
        for mode, status, code in (
            ("reject", 401, "unauthorized"),
            ("unavailable", 503, "auth_unavailable"),
        ):
            app, _, _ = self.application(RecordingAuthenticator(mode=mode))
            response = asyncio.run(
                app.handle(
                    BrokerHTTPRequest(
                        "POST",
                        "/v1/repair/decide",
                        json_headers(),
                        b"{}",
                    )
                )
            )
            self.assertEqual(response.status_code, status)
            self.assertEqual(json.loads(response.body), {"error": {"code": code}})
            self.assertNotIn("invalid", response.body.decode("utf-8"))
            self.assertNotIn("down", response.body.decode("utf-8"))

    def test_authenticator_timeout_is_server_side_bounded(self):
        app, _, _ = self.application(
            RecordingAuthenticator(mode="slow"),
            policy=BrokerHTTPEdgePolicy(auth_timeout_seconds=1),
        )
        response = asyncio.run(
            app.handle(
                BrokerHTTPRequest(
                    "POST",
                    "/v1/repair/decide",
                    json_headers(),
                    b"{}",
                )
            )
        )
        self.assertEqual(response.status_code, 503)
        self.assertEqual(json.loads(response.body)["error"]["code"], "auth_unavailable")

    def test_content_negotiation_and_header_injection_fail_closed(self):
        app, auth, _ = self.application()
        cases = (
            (
                BrokerHTTPRequest(
                    "POST",
                    "/v1/repair/decide",
                    (("Authorization", f"Bearer {RAW_TOKEN}"), ("Content-Type", "text/plain")),
                    b"{}",
                ),
                415,
            ),
            (
                BrokerHTTPRequest(
                    "POST",
                    "/v1/repair/decide",
                    json_headers() + (("X-Test", "ok\r\nInjected: true"),),
                    b"{}",
                ),
                400,
            ),
        )
        for request, status in cases:
            response = asyncio.run(app.handle(request))
            self.assertEqual(response.status_code, status)
        self.assertEqual(auth.tokens, [])

    def test_oversized_body_fails_before_authentication(self):
        app, auth, _ = self.application(policy=BrokerHTTPEdgePolicy(max_body_bytes=1024))
        response = asyncio.run(
            app.handle(
                BrokerHTTPRequest(
                    "POST",
                    "/v1/repair/decide",
                    json_headers(),
                    b"x" * 1025,
                )
            )
        )
        self.assertEqual(response.status_code, 413)
        self.assertEqual(auth.tokens, [])

    def test_malformed_broker_request_returns_generic_400_after_auth(self):
        app, auth, invoker = self.application()
        response = asyncio.run(
            app.handle(
                BrokerHTTPRequest(
                    "POST",
                    "/v1/repair/decide",
                    json_headers(),
                    b"{}",
                )
            )
        )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(json.loads(response.body), {"error": {"code": "invalid_request"}})
        self.assertEqual(auth.tokens, [RAW_TOKEN])
        self.assertEqual(invoker.calls, 0)

    def test_malformed_provider_decision_returns_generic_502(self):
        app, _, _ = self.application(invoker=RecordingInvoker(invalid=True))
        transport = ApplicationTransport(app)
        model = ProviderBrokerRepairModel(
            self.binding,
            FakeCredentialSource(),
            transport,
            ProviderBrokerBudget(
                max_cost_usd_per_call=Decimal("0.10"),
                max_total_cost_usd=Decimal("0.20"),
            ),
        )
        with self.assertRaises(ProviderBrokerProtocolError):
            asyncio.run(model.decide(turn()))
        response = transport.responses[-1]
        self.assertEqual(response.status_code, 502)
        self.assertEqual(json.loads(response.body), {"error": {"code": "provider_failure"}})
        self.assertNotIn("not_allowed", response.body.decode("utf-8"))

    def test_all_error_responses_are_no_store_json(self):
        app, _, _ = self.application()
        response = asyncio.run(
            app.handle(BrokerHTTPRequest("GET", "/bad", (), b""))
        )
        headers = dict(response.headers)
        self.assertEqual(headers["Content-Type"], "application/json")
        self.assertEqual(headers["Cache-Control"], "no-store")
        self.assertEqual(headers["X-Content-Type-Options"], "nosniff")

    def test_edge_policy_bounds(self):
        with self.assertRaises(ValueError):
            BrokerHTTPEdgePolicy(max_header_count=0)
        with self.assertRaises(ValueError):
            BrokerHTTPEdgePolicy(max_bearer_token_chars=8)
        with self.assertRaises(ValueError):
            BrokerHTTPEdgePolicy(auth_timeout_seconds=0)


if __name__ == "__main__":
    unittest.main()
