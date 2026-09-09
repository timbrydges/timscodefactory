#!/usr/bin/env python3
"""Run one real Docker-backed, zero-cost brokered CI repair canary.

The canary is deliberately non-authoritative and vendor-free. It reproduces a
known failing command in the hardened Docker runtime, feeds sanitized context to
a scripted provider-broker transport, applies one bounded edit in a disposable
candidate workspace, re-runs the exact original command in Docker, persists the
metadata-only trace in SQLite, reopens/replays it, and verifies the authoritative
fixture never changed.
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
)
from factory_runtime.repair import RepairPolicy, RepairRequest, VerifiedRepairCandidate  # noqa: E402
from factory_runtime.structured_repair import StructuredRepairPolicy  # noqa: E402
from factory_runtime.trace_store_sqlite import SQLiteBrokeredRepairTraceStore  # noqa: E402


PINNED_PYTHON_IMAGE = re.compile(r"^python@sha256:[0-9a-f]{64}$")
COMMIT = re.compile(r"^[0-9a-f]{40}$")
CANARY_TOKEN = "factory-broker-canary-token-0001"


class CanaryCredentialSource:
    async def issue(self, *, audience: str) -> EphemeralBrokerCredential:
        now = datetime.now(timezone.utc)
        return EphemeralBrokerCredential(
            token=CANARY_TOKEN,
            audience=audience,
            issued_at=now - timedelta(seconds=1),
            expires_at=now + timedelta(minutes=5),
        )


class ScriptedZeroCostBrokerTransport:
    def __init__(self) -> None:
        self.calls: list[dict[str, object]] = []
        self._decisions = [
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

    async def post_json(self, *, endpoint, headers, body, timeout_seconds):
        if endpoint != "https://provider-broker.internal/v1/repair/decide":
            raise AssertionError("broker canary was routed to an unapproved endpoint")
        if headers.get("Authorization") != f"Bearer {CANARY_TOKEN}":
            raise AssertionError("broker canary did not use the expected ephemeral credential")
        payload = json.loads(body.decode("utf-8"))
        if payload.get("provider_profile") != "coding_primary":
            raise AssertionError("broker canary provider profile drifted")
        if payload.get("model_selector") != "FACTORY_CODING_MODEL":
            raise AssertionError("broker canary model selector drifted")
        if not self._decisions:
            raise AssertionError("broker canary made an unexpected extra model call")
        self.calls.append(
            {
                "request_id": payload["request_id"],
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
            "decision": self._decisions.pop(0),
            "usage": {
                "input_tokens": 0,
                "output_tokens": 0,
                "cost_usd": "0.00",
            },
        }
        return BrokerHTTPResponse(
            status_code=200,
            body=json.dumps(response, sort_keys=True, separators=(",", ":")).encode("utf-8"),
        )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--workspace", required=True, type=Path)
    parser.add_argument("--image-ref", required=True)
    parser.add_argument("--source-commit", required=True)
    return parser.parse_args()


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
    transport = ScriptedZeroCostBrokerTransport()
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
            CanaryCredentialSource(),
            transport,
            budget,
            structured_policy=StructuredRepairPolicy(max_model_turns=3),
            repair_policy=RepairPolicy(max_attempts=2),
            trace_store=trace_store,
        )
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
                "repair_attempt": outcome.attempt_number,
                "trace_id": artifact.trace_id,
                "trace_events": artifact.replay.event_count,
                "trace_final_digest": artifact.replay.final_event_digest,
                "failure_fingerprint": artifact.failure_fingerprint.digest,
                "fingerprint_seen_count": history.seen_count,
                "authoritative_workspace_unchanged": True,
                "candidate_verified": True,
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
