from __future__ import annotations

import asyncio
import os
import sqlite3
import sys
import tempfile
import unittest
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tests"))

from factory_runtime.brokered_repair import compose_brokered_ci_repair_runtime  # noqa: E402
from factory_runtime.brokered_repair_trace import build_brokered_repair_trace  # noqa: E402
from factory_runtime.repair import RepairEscalation, RepairEscalationReason, RepairPolicy, VerifiedRepairCandidate  # noqa: E402
from factory_runtime.structured_repair import StructuredRepairPolicy  # noqa: E402
from factory_runtime.trace_store_sqlite import (  # noqa: E402
    SQLiteBrokeredRepairTraceStore,
    SQLiteTraceStoreError,
)
from test_brokered_ci_repair_runtime import (  # noqa: E402
    FakeCredentialSource,
    FakePipelineFactory,
    ScriptedBrokerTransport,
    broker_budget,
    repair_request,
)


def escalation_artifact(*, offset_seconds: int = 0):
    request = repair_request()
    outcome = RepairEscalation(
        reason=RepairEscalationReason.INITIAL_RUNTIME_FAILURE,
        attempts=0,
        initial_failure=None,
        last_failure=None,
    )
    return build_brokered_repair_trace(
        request,
        outcome,
        (),
        # Keep distinct synthetic starts safely in the past; telemetry correctly
        # rejects traces whose declared start is later than their first event.
        started_at=datetime.now(timezone.utc) - timedelta(seconds=10 - offset_seconds),
    )


class SQLiteTraceStoreTests(unittest.TestCase):
    def test_store_reopen_get_and_fingerprint_history(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "factory-traces.sqlite3"
            store = SQLiteBrokeredRepairTraceStore(path)
            first = escalation_artifact(offset_seconds=0)
            second = escalation_artifact(offset_seconds=1)
            self.assertEqual(first.failure_fingerprint.digest, second.failure_fingerprint.digest)

            store.store(first)
            store.store(second)
            reopened = SQLiteBrokeredRepairTraceStore(path)

            self.assertEqual(reopened.get(first.trace_id), first)
            matches = reopened.find_by_fingerprint(first.failure_fingerprint.digest)
            self.assertEqual([item.trace_id for item in matches], [second.trace_id, first.trace_id])
            summary = reopened.summarize_fingerprint(first.failure_fingerprint.digest)
            self.assertIsNotNone(summary)
            assert summary is not None
            self.assertEqual(summary.seen_count, 2)
            self.assertEqual(summary.successful_count, 0)
            self.assertEqual(summary.escalated_count, 2)
            self.assertIsNone(summary.lowest_success_cost_usd)
            self.assertEqual(summary.latest_trace_id, second.trace_id)
            self.assertEqual(os.stat(path).st_mode & 0o777, 0o600)

    def test_idempotent_same_trace_and_conflicting_trace_id_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            store = SQLiteBrokeredRepairTraceStore(Path(temp) / "trace.sqlite3")
            artifact = escalation_artifact()
            store.store(artifact)
            store.store(artifact)
            conflict = replace(artifact, repair_id="different-repair-id")
            with self.assertRaises(SQLiteTraceStoreError):
                store.store(conflict)

    def test_capacity_fails_closed_without_eviction(self):
        with tempfile.TemporaryDirectory() as temp:
            store = SQLiteBrokeredRepairTraceStore(
                Path(temp) / "trace.sqlite3",
                max_records=1,
            )
            first = escalation_artifact(offset_seconds=0)
            second = escalation_artifact(offset_seconds=1)
            store.store(first)
            with self.assertRaises(SQLiteTraceStoreError):
                store.store(second)
            self.assertEqual(store.get(first.trace_id), first)

    def test_tampered_persisted_summary_is_detected_on_read(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "trace.sqlite3"
            store = SQLiteBrokeredRepairTraceStore(path)
            artifact = escalation_artifact()
            store.store(artifact)
            with sqlite3.connect(path) as connection:
                connection.execute(
                    "UPDATE repair_traces SET terminal_status='SUCCEEDED' WHERE trace_id=?",
                    (artifact.trace_id,),
                )
            with self.assertRaises(SQLiteTraceStoreError):
                store.get(artifact.trace_id)

    def test_composed_runtime_persists_success_and_exact_fingerprint(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            authoritative = root / "target"
            authoritative.mkdir()
            (authoritative / "app.py").write_text(
                "def value():\n    return 1\n",
                encoding="utf-8",
            )
            database = root / "runtime-traces.sqlite3"
            store = SQLiteBrokeredRepairTraceStore(database)
            runtime = compose_brokered_ci_repair_runtime(
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

            outcome, artifact = asyncio.run(runtime.repair_with_trace(repair_request()))

            self.assertIsInstance(outcome, VerifiedRepairCandidate)
            reopened = SQLiteBrokeredRepairTraceStore(database)
            restored = reopened.get(artifact.trace_id)
            self.assertEqual(restored, artifact)
            history = reopened.summarize_fingerprint(artifact.failure_fingerprint.digest)
            self.assertIsNotNone(history)
            assert history is not None
            self.assertEqual(history.seen_count, 1)
            self.assertEqual(history.successful_count, 1)
            self.assertEqual(history.escalated_count, 0)
            self.assertEqual(history.lowest_success_cost_usd, artifact.replay.total_provider_cost_usd)
            assert isinstance(outcome, VerifiedRepairCandidate)
            outcome.cleanup()

    def test_rejects_symlink_database_path(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            target = root / "actual.sqlite3"
            target.touch()
            link = root / "linked.sqlite3"
            link.symlink_to(target)
            with self.assertRaises(SQLiteTraceStoreError):
                SQLiteBrokeredRepairTraceStore(link)


if __name__ == "__main__":
    unittest.main()
