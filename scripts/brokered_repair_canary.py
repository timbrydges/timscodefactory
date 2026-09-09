#!/usr/bin/env python3
"""Run one real Docker-backed, zero-cost broker-service CI repair canary.

The canary is deliberately non-authoritative and vendor-free. It reproduces a
known failing command in the hardened Docker runtime, routes the repair model
through the real Factory HTTP edge, Bearer authenticator, broker service,
registry-backed model selector and zero-cost dry-run provider, applies one
bounded edit in a disposable candidate workspace, re-runs the exact original
command in Docker, persists the metadata-only trace in SQLite, reopens/replays
it, and verifies the authoritative fixture never changed.

This exercises the broker HTTP application boundary in-process. It does not open
a network socket or terminate TLS; those remain deployment concerns.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import re
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from pathlib import Path
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from factory_runtime.brokered_repair import build_docker_brokered_ci_repair_runtime  # noqa: E402
from factory_runtime.detector import BaseImagePolicy  # noqa: E402
from factory_runtime.docker_provisioner import DockerProvisioningPolicy  # noqa: E402
from factory_runtime.docker_sandbox import workspace_tree_digest  # noqa: E402
from factory_runtime.provider_broker import (  # noqa: E402
    BrokerHTTPResponse,
    EphemeralBrokerCredential,
    ProviderBrokerBudget,
    load_provider_broker_binding,
)
from factory_runtime.provider_broker_http import (  # noqa: E402
    BrokerHTTPRequest,
    ReferenceProviderBrokerHTTPApplication,
)
from factory_runtime.provider_broker_service import (  # noqa: E402
    BrokerAuthContext,
    ReferenceProviderBrokerService,
)
from factory_runtime.provider_targets import (  # noqa: E402
    CatalogProviderSelectorResolver,
    DryRunProviderInvoker,
    ScriptedDryRunDecisionEngine,
    StaticProviderSelectorValueSource,
)
from factory_runtime.repair import RepairPolicy, RepairRequest, VerifiedRepairCandidate  # noqa: E402
from factory_runtime.structured_repair import StructuredRepairPolicy  # noqa: E402
from factory_runtime.trace_store_sqlite import SQLiteBrokeredRepairTraceStore  # noqa: E402


PINNED_PYTHON_IMAGE = re.compile(r"^python@sha256:[0-9a-f]{64}$")
COMMIT = re.compile(r"^[0-9a-f]{40}$")
CANARY_TOKEN = "factory-broker-canary-token-0001"
BROKER_ENDPOINT = "https://provider-broker.internal/v1/repair/decide"


class CanaryCredentialSource:
    """Issue the client-side ephemeral canary credential."""

    def __init__(self) -> None:
        self.issue_count = 0

    async def issue(self, *, audience: str) -> EphemeralBrokerCredential:
        if audience != "provider-broker.internal":
            raise AssertionError("broker client requested an unexpected credential audience")
        self.issue_count += 1
        now = datetime.now(timezone.utc)
        return EphemeralBrokerCredential(
            token=CANARY_TOKEN,
            audience=audience,
            issued_at=now - timedelta(seconds=1),
            expires_at=now + timedelta(minutes=5),
        )


class CanaryBearerAuthenticator:
    """Terminate and validate the raw canary token at the HTTP edge."""

    def __init__(self) -> None:
        self.auth_count = 0

    async def authenticate(self, token: str) -> BrokerAuthContext:
        if token != CANARY_TOKEN:
            raise AssertionError("broker HTTP edge received an unexpected Bearer token")
        self.auth_count += 1
        now = datetime.now(timezone.utc)
        return BrokerAuthContext(
            subject="engineering_agent_service",
            audience="provider-broker.internal",
            issued_at=now - timedelta(seconds=1),
            expires_at=now + timedelta(minutes=5),
        )


class InProcessBrokerHTTPTransport:
    """Bridge the client transport protocol to the real HTTP application edge.

    This deliberately does not bypass the HTTP request model: client headers and
    body are converted into BrokerHTTPRequest, authenticated and validated by
    ReferenceProviderBrokerHTTPApplication, then normalized back into the
    client's BrokerHTTPResponse type.
    """

    def __init__(self, application: ReferenceProviderBrokerHTTPApplication) -> None:
        self.application = application
        self.calls: list[dict[str, object]] = []

    async def post_json(self, *, endpoint, headers, body, timeout_seconds):
        if endpoint != BROKER_ENDPOINT:
            raise AssertionError("broker canary was routed to an unapproved endpoint")
        parsed = urlparse(endpoint)
        if parsed.scheme != "https" or parsed.hostname != "provider-broker.internal":
            raise AssertionError("broker canary endpoint lost its approved HTTPS binding")
        request = BrokerHTTPRequest(
            method="POST",
            path=parsed.path,
            headers=tuple(headers.items()),
            body=body,
        )
        response = await asyncio.wait_for(
            self.application.handle(request),
            timeout=timeout_seconds,
        )
        response_headers = {name.lower(): value for name, value in response.headers}
        self.calls.append(
            {
                "status_code": response.status_code,
                "cache_control": response_headers.get("cache-control"),
                "content_type": response_headers.get("content-type"),
            }
        )
        return BrokerHTTPResponse(status_code=response.status_code, body=response.body)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--workspace", required=True, type=Path)
    parser.add_argument("--image-ref", required=True)
    parser.add_argument("--source-commit", required=True)
    return parser.parse_args()


def build_broker_chain():
    binding = load_provider_broker_binding(ROOT)
    selector = CatalogProviderSelectorResolver(
        ROOT,
        StaticProviderSelectorValueSource(
            {"FACTORY_CODING_MODEL": "coding_primary_dry_run"}
        ),
    )
    decision_engine = ScriptedDryRunDecisionEngine(
        decisions=[
            {"type": "read_files", "paths": ["app.py"]},
            {
                "type": "apply_edits",
                "summary": "repair canary return value",
                "edits": [
                    {
                        "path": "app.py",
                        "old_text": "return 1",
                        "new_text": "return 2",
                    }
                ],
            },
        ]
    )
    provider_invoker = DryRunProviderInvoker(decision_engine)
    service = ReferenceProviderBrokerService(
        ROOT,
        binding,
        selector,
        provider_invoker,
    )
    authenticator = CanaryBearerAuthenticator()
    application = ReferenceProviderBrokerHTTPApplication(service, authenticator)
    transport = InProcessBrokerHTTPTransport(application)
    credential_source = CanaryCredentialSource()
    return (
        binding,
        credential_source,
        authenticator,
        provider_invoker,
        decision_engine,
        transport,
    )


async def run_canary(workspace: Path, image_ref: str, source_commit: str) -> dict[str, object]:
    workspace = workspace.resolve()
    if not workspace.is_dir():
        raise RuntimeError("brokered repair canary workspace does not exist")
    if not PINNED_PYTHON_IMAGE.fullmatch(image_ref):
        raise RuntimeError("brokered repair canary image must be an immutable python@sha256 reference")
    if not COMMIT.fullmatch(source_commit):
        raise RuntimeError("source commit must be an exact 40-character SHA")

    before_digest = workspace_tree_digest(workspace)
    original_source = (workspace / "app.py").read_text(encoding="utf-8")
    if "return 1" not in original_source:
        raise RuntimeError("brokered repair canary fixture is not in its expected broken state")

    image_policy = BaseImagePolicy(images=(("python:3.12", image_ref),))
    provisioning_policy = DockerProvisioningPolicy()
    (
        service_binding,
        credential_source,
        authenticator,
        provider_invoker,
        decision_engine,
        transport,
    ) = build_broker_chain()
    budget = ProviderBrokerBudget(
        max_cost_usd_per_call=Decimal("0.01"),
        max_total_cost_usd=Decimal("0.02"),
    )

    with tempfile.TemporaryDirectory(prefix="factory-brokered-repair-canary-") as temp:
        database_path = Path(temp) / "traces.sqlite3"
        trace_store = SQLiteBrokeredRepairTraceStore(database_path, max_records=8)
        runtime = build_docker_brokered_ci_repair_runtime(
            ROOT,
            workspace,
            image_policy,
            provisioning_policy,
            credential_source,
            transport,
            budget,
            structured_policy=StructuredRepairPolicy(max_model_turns=3),
            repair_policy=RepairPolicy(max_attempts=2),
            trace_store=trace_store,
        )
        if runtime.binding.binding_digest != service_binding.binding_digest:
            raise RuntimeError("client and broker service resolved different Factory bindings")

        request = RepairRequest(
            repair_id="real-brokered-repair-canary-v1",
            task_id="real-brokered-repair-canary-task",
            lease_id="real-brokered-repair-canary-lease",
            role_id="engineering_agent",
            source_commit=source_commit,
            command=("python", "-m", "unittest", "discover", "-s", "tests", "-v"),
            expected_provisioner_identity="factory_docker_provisioner_v1",
            expected_runner_identity="factory_docker_sandbox_v1",
            provisioning_timeout_seconds=300,
            verification_timeout_seconds=180,
        )

        outcome, artifact = await runtime.repair_with_trace(request)
        if not isinstance(outcome, VerifiedRepairCandidate):
            raise RuntimeError(f"brokered repair canary escalated instead of repairing: {outcome}")

        try:
            if workspace_tree_digest(workspace) != before_digest:
                raise RuntimeError("authoritative brokered repair fixture changed during canary")
            if (workspace / "app.py").read_text(encoding="utf-8") != original_source:
                raise RuntimeError("authoritative brokered repair source changed during canary")
            candidate_source = (outcome.workspace / "app.py").read_text(encoding="utf-8")
            if "return 2" not in candidate_source or "return 1" in candidate_source:
                raise RuntimeError("verified candidate does not contain the expected bounded repair")
            if outcome.verification.receipt.exit_code != 0 or outcome.verification.receipt.timed_out:
                raise RuntimeError("verified candidate did not pass the exact original command")
            if outcome.attempt_number != 1:
                raise RuntimeError("brokered repair canary required an unexpected number of attempts")

            if len(runtime.provider_calls) != 2 or len(transport.calls) != 2:
                raise RuntimeError("brokered repair canary did not use exactly two broker decisions")
            if credential_source.issue_count != 2 or authenticator.auth_count != 2:
                raise RuntimeError("broker credential issuance/authentication count is inconsistent")
            if provider_invoker.invocation_count != 2 or decision_engine.decisions:
                raise RuntimeError("dry-run provider service did not consume exactly two decisions")
            if any(call["status_code"] != 200 for call in transport.calls):
                raise RuntimeError("broker HTTP application returned a non-200 response")
            if any(call["cache_control"] != "no-store" for call in transport.calls):
                raise RuntimeError("broker HTTP response did not enforce no-store")
            if any(call["content_type"] != "application/json" for call in transport.calls):
                raise RuntimeError("broker HTTP response content type drifted")
            if runtime.spent_usd != Decimal("0.00"):
                raise RuntimeError("zero-cost broker canary reported nonzero provider spend")

            if artifact.replay.terminal_status != "SUCCEEDED":
                raise RuntimeError("repair trace replay did not reconstruct success")
            if artifact.replay.model_calls != 2 or artifact.replay.repair_actions != 1:
                raise RuntimeError("repair trace replay counts are inconsistent")
            if artifact.replay.total_provider_cost_usd != Decimal("0.00"):
                raise RuntimeError("repair trace replay reported nonzero provider cost")

            persisted = SQLiteBrokeredRepairTraceStore(database_path, max_records=8)
            loaded = persisted.get(artifact.trace_id)
            if loaded != artifact:
                raise RuntimeError("persisted repair trace did not round-trip exactly")
            history = persisted.summarize_fingerprint(artifact.failure_fingerprint.digest)
            if history is None:
                raise RuntimeError("repair failure fingerprint was not indexed")
            if history.seen_count != 1 or history.successful_count != 1 or history.escalated_count != 0:
                raise RuntimeError("repair failure fingerprint history is inconsistent")
            if history.lowest_success_cost_usd != Decimal("0.00"):
                raise RuntimeError("repair failure fingerprint history reported nonzero success cost")

            trace_text = artifact.jsonl.decode("utf-8")
            for forbidden in (CANARY_TOKEN, "return 1", "return 2", "AssertionError"):
                if forbidden in trace_text:
                    raise RuntimeError("repair trace leaked forbidden raw content")

            return {
                "status": "PASS",
                "provider_cost_usd": format(runtime.spent_usd, "f"),
                "provider_calls": len(runtime.provider_calls),
                "broker_http_calls": len(transport.calls),
                "broker_authentications": authenticator.auth_count,
                "provider_invocations": provider_invoker.invocation_count,
                "provider_target": "coding_primary_dry_run",
                "repair_attempt": outcome.attempt_number,
                "trace_id": artifact.trace_id,
                "trace_events": artifact.replay.event_count,
                "trace_final_digest": artifact.replay.final_event_digest,
                "failure_fingerprint": artifact.failure_fingerprint.digest,
                "fingerprint_seen_count": history.seen_count,
                "authoritative_workspace_unchanged": True,
                "candidate_verified": True,
                "http_application_edge_exercised": True,
                "network_socket_opened": False,
                "paid_provider_traffic": False,
                "factory_state_mutation": False,
            }
        finally:
            outcome.cleanup()


def main() -> int:
    args = parse_args()
    summary = asyncio.run(run_canary(args.workspace, args.image_ref, args.source_commit))
    print(json.dumps(summary, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
