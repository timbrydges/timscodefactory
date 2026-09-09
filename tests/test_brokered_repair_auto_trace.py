from __future__ import annotations

import asyncio
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from decimal import Decimal
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tests"))

from factory_runtime.brokered_repair import compose_brokered_ci_repair_runtime  # noqa: E402
from factory_runtime.brokered_repair_trace import (  # noqa: E402
    InMemoryBrokeredRepairTraceStore,
    build_brokered_repair_trace,
    fingerprint_runtime_failure,
)
from factory_runtime.pipeline import RuntimeInvocation  # noqa: E402
from factory_runtime.repair import RepairEscalation, RepairEscalationReason, RepairPolicy, VerifiedRepairCandidate  # noqa: E402
from factory_runtime.structured_repair import StructuredRepairPolicy  # noqa: E402
from factory_runtime.telemetry import parse_runtime_trace_jsonl  # noqa: E402
from test_brokered_ci_repair_runtime import (  # noqa: E402
    COMMIT,
    FakeCredentialSource,
    FakePipelineFactory,
    ScriptedBrokerTransport,
    broker_budget,
    make_observation,
    repair_request,
)


class BrokeredRepairAutoTraceTests(unittest.TestCase):
    def _runtime(self, authoritative: Path, store: InMemoryBrokeredRepairTraceStore):
        return compose_brokered_ci_repair_runtime(
            ROOT,
            authoritative,
            FakePipelineFactory(),
            FakeCredentialSource(),
            ScriptedBrokerTransport(),
            broker_budget(),
            structured_policy=StructuredRepairPolicy(max_model_turns=3),
            repair_policy=RepairPolicy(max_attempts=2),
            trace_store=store,
        )

    def test_composed_repair_automatically_stores_valid_metadata_only_trace(self):
        with tempfile.TemporaryDirectory() as temp:
            authoritative = Path(temp) / "target"
            authoritative.mkdir()
            (authoritative / "app.py").write_text(
                "def value():\n    return 1\n",
                encoding="utf-8",
            )
            store = InMemoryBrokeredRepairTraceStore()
            runtime = self._runtime(authoritative, store)

            outcome, artifact = asyncio.run(runtime.repair_with_trace(repair_request()))

            self.assertIsInstance(outcome, VerifiedRepairCandidate)
            assert isinstance(outcome, VerifiedRepairCandidate)
            self.assertEqual(artifact.repair_id, repair_request().repair_id)
            self.assertEqual(artifact.replay.terminal_status, "SUCCEEDED")
            self.assertEqual(artifact.replay.terminal_reason, "VERIFIED_REPAIR")
            self.assertEqual(artifact.replay.model_calls, 2)
            self.assertEqual(artifact.replay.repair_actions, 1)
            self.assertEqual(artifact.replay.verification_observations, 2)
            self.assertEqual(artifact.replay.total_provider_cost_usd, Decimal("0.02"))
            self.assertEqual(artifact.failure_fingerprint.digest, fingerprint_runtime_failure(outcome.initial_failure).digest)
            self.assertIs(store.get(artifact.trace_id), artifact)
            self.assertEqual(parse_runtime_trace_jsonl(artifact.jsonl), artifact.events)
            self.assertNotIn(b"AssertionError", artifact.jsonl)
            self.assertNotIn(b"expected 2, got 1", artifact.jsonl)
            self.assertNotIn(b"fix expected return value", artifact.jsonl)
            self.assertNotIn(b"return 1", artifact.jsonl)
            self.assertNotIn(b"return 2", artifact.jsonl)
            outcome.cleanup()

    def test_repair_method_remains_backward_compatible_and_still_traces(self):
        with tempfile.TemporaryDirectory() as temp:
            authoritative = Path(temp) / "target"
            authoritative.mkdir()
            (authoritative / "app.py").write_text(
                "def value():\n    return 1\n",
                encoding="utf-8",
            )
            store = InMemoryBrokeredRepairTraceStore()
            runtime = self._runtime(authoritative, store)

            outcome = asyncio.run(runtime.repair(repair_request()))

            self.assertIsInstance(outcome, VerifiedRepairCandidate)
            self.assertEqual(len(store.artifacts), 1)
            self.assertEqual(store.artifacts[0].replay.terminal_status, "SUCCEEDED")
            assert isinstance(outcome, VerifiedRepairCandidate)
            outcome.cleanup()

    def test_exact_failure_fingerprint_ignores_task_and_lease_identity(self):
        with tempfile.TemporaryDirectory() as first_temp, tempfile.TemporaryDirectory() as second_temp:
            first = Path(first_temp)
            second = Path(second_temp)
            (first / "app.py").write_text("def value():\n    return 1\n", encoding="utf-8")
            (second / "app.py").write_text("def value():\n    return 1\n", encoding="utf-8")
            one = RuntimeInvocation(
                run_id="run-one",
                task_id="task-one",
                lease_id="lease-one",
                role_id="engineering_agent",
                source_commit=COMMIT,
                command=("python", "-m", "pytest", "-q"),
                expected_provisioner_identity="fake_provisioner_v1",
                expected_runner_identity="fake_verifier_v1",
            )
            two = RuntimeInvocation(
                run_id="run-two",
                task_id="task-two",
                lease_id="lease-two",
                role_id="engineering_agent",
                source_commit=COMMIT,
                command=("python", "-m", "pytest", "-q"),
                expected_provisioner_identity="fake_provisioner_v1",
                expected_runner_identity="fake_verifier_v1",
            )
            first_failure = make_observation(first, one, exit_code=1)
            second_failure = make_observation(second, two, exit_code=1)

            self.assertEqual(
                fingerprint_runtime_failure(first_failure).digest,
                fingerprint_runtime_failure(second_failure).digest,
            )

    def test_unbound_initial_runtime_failure_still_produces_escalation_trace(self):
        request = repair_request()
        outcome = RepairEscalation(
            reason=RepairEscalationReason.INITIAL_RUNTIME_FAILURE,
            attempts=0,
            initial_failure=None,
            last_failure=None,
        )
        artifact = build_brokered_repair_trace(
            request,
            outcome,
            (),
            started_at=datetime.now(timezone.utc),
        )
        self.assertEqual(artifact.replay.terminal_status, "ESCALATED")
        self.assertEqual(artifact.replay.terminal_reason, "INITIAL_RUNTIME_FAILURE")
        self.assertEqual(artifact.replay.model_calls, 0)
        self.assertEqual(artifact.replay.verification_observations, 0)


if __name__ == "__main__":
    unittest.main()
