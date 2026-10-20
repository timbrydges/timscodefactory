from __future__ import annotations

import asyncio
import json
import sys
import unittest
from jsonschema import Draft202012Validator
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
    _decision_schema,
    _extract_structured_output,
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
    def test_task_wire_schema_and_normalizer_agree_on_each_decision(self):
        schema = _decision_schema('task_implementation')
        Draft202012Validator.check_schema(schema)
        validator = Draft202012Validator(schema)
        self.assertEqual(schema['type'], 'object')
        self.assertNotIn('anyOf', schema)
        for decision in (
            {'type': 'read_files', 'paths': ['app.py']},
            {'type': 'apply_edits', 'summary': 'Add pagination', 'edits': [
                {'path': 'new.py', 'old_text': '', 'new_text': 'content'}]},
            {'type': 'escalate', 'reason': 'Missing context'},
        ):
            wire = {'decision': decision}
            validator.validate(wire)
            self.assertEqual(_extract_structured_output(provider_payload(wire), 'task_implementation'), decision)

    def test_task_schema_rejects_contradictory_unknown_and_empty_decisions(self):
        validator = Draft202012Validator(_decision_schema('task_implementation'))
        for wire in (
            {'decision': {'type': 'read_files', 'paths': ['app.py'], 'reason': 'explanation'}},
            {'decision': {'type': 'read_files', 'paths': []}},
            {'decision': {'type': 'apply_edits', 'summary': 'change', 'edits': []}},
            {'decision': {'type': 'escalate', 'reason': ''}},
            {'decision': {'type': ['escalate'], 'reason': 'stop'}},
            {'decision': {'type': 'escalate', 'reason': 'stop'}, 'extra': 'ignored?'},
        ):
            with self.subTest(wire=wire):
                self.assertFalse(validator.is_valid(wire))
                with self.assertRaises(OpenAIProviderProtocolError):
                    _extract_structured_output(provider_payload(wire), 'task_implementation')

    def test_preexisting_wire_schema_gap_is_reproduced_offline(self):
        contradictory = read_files_decision()
        contradictory['reason'] = 'This explanation was allowed by the old wire schema'
        Draft202012Validator(_decision_schema('ci_repair')).validate(contradictory)
        with self.assertRaises(OpenAIProviderProtocolError) as caught:
            _extract_structured_output(provider_payload(contradictory))
        self.assertEqual(caught.exception.failure_code, 'decision_fields_contradictory')
        self.assertFalse(Draft202012Validator(_decision_schema('task_implementation')).is_valid(
            {'decision': contradictory}))

    def test_safe_diagnostics_distinguish_json_text_and_envelope_failures(self):
        for change, code in (
            ({'output': []}, 'output_text_count_invalid'),
            ({'output': [{'type': 'message', 'content': [{'type': 'output_text', 'text': 'not JSON'}]}]}, 'output_json_invalid'),
            ({'error': {'message': 'private'}}, 'response_failure_details'),
        ):
            payload = provider_payload({'decision': {'type': 'escalate', 'reason': 'stop'}})
            payload.update(change)
            with self.assertRaises(OpenAIProviderProtocolError) as caught:
                _extract_structured_output(payload, 'task_implementation')
            self.assertEqual(caught.exception.failure_code, code)

    def test_task_edit_shape_failures_have_exact_safe_codes(self):
        for edit, code in (({'path': 'x'}, 'edit_keys_invalid'),
                           ({'path': 'x', 'old_text': '', 'new_text': 1}, 'edit_fields_invalid')):
            wire = {'decision': {'type': 'apply_edits', 'summary': 'change', 'edits': [edit]}}
            with self.assertRaises(OpenAIProviderProtocolError) as caught:
                _extract_structured_output(provider_payload(wire), 'task_implementation')
            self.assertEqual(caught.exception.failure_code, code)

    def test_failure_evidence_is_bounded_redacted_and_reset(self):
        payload = provider_payload(read_files_decision(), output_tokens=4096)
        payload.update(status='incomplete', incomplete_details={'reason': 'max_output_tokens'},
                       output=[{'text': 'private response'}])
        payload['usage']['output_tokens_details']['reasoning_tokens'] = 4096
        invoker, _, _, transport = make_invoker(
            ProviderHTTPResponse(200, json.dumps(payload).encode()), live_enabled=True)
        def invoke():
            return asyncio.run(invoker.invoke(target=TARGET, turn={}, max_cost_usd=Decimal('1'),
                                              decision_schema_version='1'))
        with self.assertRaises(OpenAIProviderProtocolError) as caught:
            invoke()
        self.assertEqual(caught.exception.failure_code, 'output_token_limit')
        self.assertEqual(invoker.last_response_evidence, {
            'model_matches': True, 'response_status': 'incomplete',
            'incomplete_reason': 'max_output_tokens', 'input_tokens': 1000,
            'output_tokens': 4096, 'reasoning_tokens': 4096})
        # Independent offline invocation proves stale evidence is cleared even on HTTP failure.
        transport.response = ProviderHTTPResponse(500, b'private body')
        with self.assertRaises(OpenAIProviderProtocolError):
            invoke()
        self.assertEqual(invoker.last_response_evidence, {})

    def test_mismatch_retains_only_safe_metadata_and_keeps_strict_validation(self):
        payload = provider_payload(read_files_decision(), model='private unexpected model')
        payload['usage'] = {'input_tokens': True, 'output_tokens': 10**30,
                            'output_tokens_details': {'reasoning_tokens': 'private'}}
        payload['status'] = 'private status'
        invoker, _, _, _ = make_invoker(ProviderHTTPResponse(200, json.dumps(payload).encode()),
                                      live_enabled=True)
        with self.assertRaises(OpenAIProviderProtocolError) as caught:
            asyncio.run(invoker.invoke(target=TARGET, turn={}, max_cost_usd=Decimal('1'),
                                      decision_schema_version='1'))
        self.assertEqual(caught.exception.failure_code, 'model_mismatch')
        self.assertEqual(invoker.last_response_evidence, {'model_matches': False})

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
        self.assertEqual(request["service_tier"], "default")
        self.assertEqual(request["prompt_cache_options"], {"mode": "explicit"})
        self.assertNotIn("prompt_cache_breakpoint", transport.last_body.decode())
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


    def test_large_review_fits_smaller_output_allowance_and_preserves_cost_gate(self):
        turn = {'kind': 'factory_task_review_v1', 'fixture': 'x' * 25000}
        response = ProviderHTTPResponse(200, json.dumps(provider_payload({
            'review_input_digest': 'sha256:' + 'a'*64, 'verdict': 'REJECT',
            'findings': ['Offline fixture only']})).encode())
        for output, byte_cap, expected in [
                (8192, 21540, OpenAIProviderProtocolError),
                (8192, 42020, OpenAIProviderPricingError),
                (4096, 42020, None)]:
            with self.subTest(output=output, byte_cap=byte_cap):
                credentials = CountingCredentialSource()
                transport = RecordingTransport(response)
                invoker = OpenAIResponsesProviderInvoker(credentials, StaticPricingSource(), transport,
                    policy=OpenAIProviderPolicy(live_enabled=True, workload='task_review',
                        max_output_tokens=output, max_request_bytes=byte_cap))
                call = invoker.invoke(target=TARGET, turn=turn,
                    max_cost_usd=Decimal('0.25'), decision_schema_version='1')
                if expected:
                    with self.assertRaises(expected) as caught:
                        asyncio.run(call)
                    if expected is OpenAIProviderProtocolError:
                        self.assertEqual(caught.exception.failure_code, 'request_byte_limit')
                    self.assertEqual(credentials.calls, 0)
                    self.assertEqual(transport.calls, 0)
                else:
                    asyncio.run(call)
                    self.assertEqual(transport.calls, 1)
                    self.assertEqual(json.loads(transport.last_body)['max_output_tokens'], 4096)


if __name__ == "__main__":
    unittest.main()
