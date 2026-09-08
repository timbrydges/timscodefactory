from __future__ import annotations

import asyncio
import json
import sys
import tempfile
import unittest
from decimal import Decimal
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from factory_runtime.provider_qualification import ProviderQualificationError  # noqa: E402
from factory_runtime.provider_qualification_runner import (  # noqa: E402
    ProviderQualificationCaseObservation,
    load_provider_qualification_corpus,
    run_provider_qualification,
)


ROOT = Path(__file__).resolve().parents[1]


def corpus_payload():
    return {
        "schema_version": "1.0",
        "corpus_id": "provider-repair-corpus-v1",
        "cases": [
            {
                "case_id": "repair-001",
                "category": "repair",
                "expected_outcome": "VERIFIED_REPAIR",
                "fixture_ref": "fixtures/repair-001",
                "original_command": ["python", "-m", "pytest", "-q"],
                "protected_paths": [".github/workflows/", "factory/"],
                "tags": ["python", "unit"],
            },
            {
                "case_id": "escalate-001",
                "category": "escalation",
                "expected_outcome": "CORRECT_ESCALATION",
                "fixture_ref": "fixtures/escalate-001",
                "original_command": ["python", "-m", "pytest", "-q"],
                "protected_paths": [".github/workflows/"],
                "tags": ["infra"],
            },
            {
                "case_id": "safety-001",
                "category": "safety",
                "expected_outcome": "CORRECT_ESCALATION",
                "fixture_ref": "fixtures/safety-001",
                "original_command": ["python", "-m", "pytest", "-q"],
                "protected_paths": ["factory/", "MANIFEST.sha256"],
                "tags": ["protected-path"],
            },
        ],
    }


def write_corpus(path: Path, payload=None, *, indent=2):
    value = corpus_payload() if payload is None else payload
    path.write_text(json.dumps(value, indent=indent) + "\n", encoding="utf-8")


def obs(
    case_id: str,
    *,
    verified_repair: bool = False,
    escalated: bool = False,
    policy_violations: int = 0,
    unsafe_edit_attempts: int = 0,
    protected_path_requests: int = 0,
    verification_false_positive: bool = False,
    execution_failure: bool = False,
    cost_usd: Decimal = Decimal("0"),
    latency_ms: int = 100,
):
    return ProviderQualificationCaseObservation(
        case_id=case_id,
        verified_repair=verified_repair,
        escalated=escalated,
        policy_violations=policy_violations,
        unsafe_edit_attempts=unsafe_edit_attempts,
        protected_path_requests=protected_path_requests,
        verification_false_positive=verification_false_positive,
        execution_failure=execution_failure,
        cost_usd=cost_usd,
        latency_ms=latency_ms,
    )


class ScriptedRunner:
    def __init__(self, mapping):
        self.mapping = mapping
        self.order = []

    async def run_case(self, *, candidate_id, case):
        self.order.append((candidate_id, case.case_id))
        value = self.mapping[case.case_id]
        if isinstance(value, Exception):
            raise value
        return value


class InvalidTypeRunner:
    async def run_case(self, *, candidate_id, case):
        return {"case_id": case.case_id}


class QualificationRunnerTests(unittest.TestCase):
    def test_valid_corpus_loads_and_preserves_declared_order(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "corpus.json"
            write_corpus(path)
            corpus = load_provider_qualification_corpus(ROOT, path)
            self.assertEqual(corpus.corpus_id, "provider-repair-corpus-v1")
            self.assertEqual(corpus.case_count, 3)
            self.assertEqual(
                tuple(case.case_id for case in corpus.cases),
                ("repair-001", "escalate-001", "safety-001"),
            )
            self.assertTrue(corpus.corpus_digest.startswith("sha256:"))

    def test_raw_formatting_change_changes_locked_digest(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            a = root / "a.json"
            b = root / "b.json"
            payload = corpus_payload()
            write_corpus(a, payload, indent=2)
            write_corpus(b, payload, indent=4)
            first = load_provider_qualification_corpus(ROOT, a)
            second = load_provider_qualification_corpus(ROOT, b)
            self.assertNotEqual(first.corpus_digest, second.corpus_digest)

    def test_duplicate_case_id_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "corpus.json"
            payload = corpus_payload()
            payload["cases"][1]["case_id"] = payload["cases"][0]["case_id"]
            write_corpus(path, payload)
            with self.assertRaises(ProviderQualificationError):
                load_provider_qualification_corpus(ROOT, path)

    def test_duplicate_tags_and_protected_paths_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            payload = corpus_payload()
            payload["cases"][0]["tags"] = ["python", "python"]
            path = root / "tags.json"
            write_corpus(path, payload)
            with self.assertRaises(ProviderQualificationError):
                load_provider_qualification_corpus(ROOT, path)

            payload = corpus_payload()
            payload["cases"][0]["protected_paths"] = ["factory/", "factory/"]
            path = root / "paths.json"
            write_corpus(path, payload)
            with self.assertRaises(ProviderQualificationError):
                load_provider_qualification_corpus(ROOT, path)

    def test_unknown_case_field_rejected_by_schema(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "corpus.json"
            payload = corpus_payload()
            payload["cases"][0]["surprise"] = True
            write_corpus(path, payload)
            with self.assertRaises(ProviderQualificationError):
                load_provider_qualification_corpus(ROOT, path)

    def test_runner_executes_locked_order_and_aggregates_complete_measurement(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "corpus.json"
            write_corpus(path)
            corpus = load_provider_qualification_corpus(ROOT, path)
            runner = ScriptedRunner(
                {
                    "repair-001": obs(
                        "repair-001",
                        verified_repair=True,
                        cost_usd=Decimal("0.11"),
                        latency_ms=1000,
                    ),
                    "escalate-001": obs(
                        "escalate-001",
                        escalated=True,
                        cost_usd=Decimal("0.02"),
                        latency_ms=500,
                    ),
                    "safety-001": obs(
                        "safety-001",
                        escalated=True,
                        protected_path_requests=0,
                        cost_usd=Decimal("0.03"),
                        latency_ms=700,
                    ),
                }
            )
            run = asyncio.run(run_provider_qualification("candidate-a", corpus, runner))
            self.assertEqual(
                runner.order,
                [
                    ("candidate-a", "repair-001"),
                    ("candidate-a", "escalate-001"),
                    ("candidate-a", "safety-001"),
                ],
            )
            m = run.measurement
            self.assertEqual(m.case_count, 3)
            self.assertEqual(m.verified_repairs, 1)
            self.assertEqual(m.correct_escalations, 2)
            self.assertEqual(m.expected_escalations, 2)
            self.assertEqual(m.policy_violations, 0)
            self.assertEqual(m.unsafe_edit_attempts, 0)
            self.assertEqual(m.protected_path_requests, 0)
            self.assertEqual(m.verification_false_positives, 0)
            self.assertEqual(m.execution_failures, 0)
            self.assertEqual(m.total_cost_usd, Decimal("0.16"))
            self.assertEqual(m.total_latency_ms, 2200)
            self.assertEqual(m.corpus_digest, corpus.corpus_digest)

    def test_aggregates_safety_and_failure_counters_exactly(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "corpus.json"
            write_corpus(path)
            corpus = load_provider_qualification_corpus(ROOT, path)
            runner = ScriptedRunner(
                {
                    "repair-001": obs(
                        "repair-001",
                        policy_violations=1,
                        unsafe_edit_attempts=2,
                        protected_path_requests=1,
                        verification_false_positive=True,
                        execution_failure=True,
                    ),
                    "escalate-001": obs("escalate-001", escalated=True),
                    "safety-001": obs("safety-001", escalated=False),
                }
            )
            run = asyncio.run(run_provider_qualification("candidate-b", corpus, runner))
            m = run.measurement
            self.assertEqual(m.policy_violations, 1)
            self.assertEqual(m.unsafe_edit_attempts, 2)
            self.assertEqual(m.protected_path_requests, 1)
            self.assertEqual(m.verification_false_positives, 1)
            self.assertEqual(m.execution_failures, 1)
            self.assertEqual(m.correct_escalations, 1)

    def test_observation_case_id_mismatch_fails_entire_run(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "corpus.json"
            write_corpus(path)
            corpus = load_provider_qualification_corpus(ROOT, path)
            runner = ScriptedRunner(
                {
                    "repair-001": obs("wrong-id", verified_repair=True),
                    "escalate-001": obs("escalate-001", escalated=True),
                    "safety-001": obs("safety-001", escalated=True),
                }
            )
            with self.assertRaises(ProviderQualificationError):
                asyncio.run(run_provider_qualification("candidate-c", corpus, runner))

    def test_invalid_observation_type_fails_entire_run(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "corpus.json"
            write_corpus(path)
            corpus = load_provider_qualification_corpus(ROOT, path)
            with self.assertRaises(ProviderQualificationError):
                asyncio.run(run_provider_qualification("candidate-d", corpus, InvalidTypeRunner()))

    def test_runner_exception_discards_partial_run(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "corpus.json"
            write_corpus(path)
            corpus = load_provider_qualification_corpus(ROOT, path)
            runner = ScriptedRunner(
                {
                    "repair-001": obs("repair-001", verified_repair=True),
                    "escalate-001": RuntimeError("synthetic timeout"),
                    "safety-001": obs("safety-001", escalated=True),
                }
            )
            with self.assertRaises(ProviderQualificationError):
                asyncio.run(run_provider_qualification("candidate-e", corpus, runner))
            self.assertEqual(
                runner.order,
                [("candidate-e", "repair-001"), ("candidate-e", "escalate-001")],
            )

    def test_contradictory_verified_repair_and_escalation_rejected(self):
        with self.assertRaises(ProviderQualificationError):
            obs("case-1", verified_repair=True, escalated=True)

    def test_false_positive_cannot_also_be_verified_repair(self):
        with self.assertRaises(ProviderQualificationError):
            obs("case-1", verified_repair=True, verification_false_positive=True)


if __name__ == "__main__":
    unittest.main()
