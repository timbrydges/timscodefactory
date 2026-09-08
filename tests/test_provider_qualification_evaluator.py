from __future__ import annotations

import asyncio
import shutil
import sys
import tempfile
import unittest
from decimal import Decimal
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from factory_runtime.provider_qualification import ProviderQualificationError  # noqa: E402
from factory_runtime.provider_qualification_evaluator import (  # noqa: E402
    BrokeredQualificationCandidateFactory,
    OracleBackedProviderQualificationCaseRunner,
    ProviderQualificationEvaluatorPolicy,
    QualificationModelTrace,
    TracingRepairModel,
    load_provider_qualification_oracle,
)
from factory_runtime.provider_qualification_runner import (  # noqa: E402
    ProviderQualificationCase,
    load_provider_qualification_corpus,
)
from factory_runtime.repair import (  # noqa: E402
    RepairEscalation,
    RepairEscalationReason,
    VerifiedRepairCandidate,
)
from factory_runtime.structured_repair import (  # noqa: E402
    ApplyEditsDecision,
    LiteralReplaceEdit,
    ReadFilesDecision,
)


ROOT = Path(__file__).resolve().parents[1]
CORPUS_PATH = ROOT / "factory" / "evals" / "provider-repair-corpus-v1.json"


class SequenceClock:
    def __init__(self, *values: int) -> None:
        self.values = list(values)

    def __call__(self) -> int:
        if not self.values:
            raise AssertionError("clock exhausted")
        return self.values.pop(0)


class FakeCandidateRuntime:
    def __init__(self, workspace: Path, mode: str, *, cost: str = "0.01") -> None:
        self.workspace = workspace
        self.mode = mode
        self._spent = Decimal(cost)
        self._trace = QualificationModelTrace((), (), 0)

    @property
    def spent_usd(self) -> Decimal:
        return self._spent

    @property
    def trace(self) -> QualificationModelTrace:
        return self._trace

    def _candidate_copy(self) -> Path:
        parent = Path(tempfile.mkdtemp(prefix="qualification-fake-candidate-"))
        candidate = parent / "workspace"
        shutil.copytree(self.workspace, candidate)
        return candidate

    async def repair(self, request):
        if self.mode == "escalate":
            return RepairEscalation(
                reason=RepairEscalationReason.STRATEGY_FAILURE,
                attempts=1,
                initial_failure=None,
                last_failure=None,
            )
        if self.mode == "mutate-authoritative":
            (self.workspace / "tampered.txt").write_text("unsafe\n", encoding="utf-8")
            return RepairEscalation(
                reason=RepairEscalationReason.AUTHORITATIVE_WORKSPACE_CHANGED,
                attempts=1,
                initial_failure=None,
                last_failure=None,
            )

        candidate = self._candidate_copy()
        if self.mode in {"good", "unsafe-green"}:
            app = candidate / "app.py"
            text = app.read_text(encoding="utf-8")
            text = text.replace(
                "return price + (price * percent / 100)",
                "return price - (price * percent / 100)",
            )
            app.write_text(text, encoding="utf-8")
        if self.mode == "unsafe-green":
            workflow = candidate / ".github" / "workflows" / "pwn.yml"
            workflow.parent.mkdir(parents=True, exist_ok=True)
            workflow.write_text("name: unsafe\n", encoding="utf-8")
            self._trace = QualificationModelTrace(
                read_paths=(".github/workflows/pwn.yml",),
                edit_paths=(".github/workflows/pwn.yml", "app.py"),
                escalation_count=0,
            )
        elif self.mode == "good":
            self._trace = QualificationModelTrace(
                read_paths=("app.py",),
                edit_paths=("app.py",),
                escalation_count=0,
            )

        return VerifiedRepairCandidate(
            workspace=candidate,
            workspace_digest="sha256:" + "a" * 64,
            attempt_number=1,
            verification=None,  # evaluator tests do not trust this object as hidden evidence
            initial_failure=None,
            actions=(),
        )


class FakeCandidateFactory:
    def __init__(self, mode: str, *, cost: str = "0.01") -> None:
        self.mode = mode
        self.cost = cost
        self.created: list[tuple[str, Path]] = []

    def create(self, *, candidate_id: str, workspace: Path) -> FakeCandidateRuntime:
        self.created.append((candidate_id, workspace))
        return FakeCandidateRuntime(workspace, self.mode, cost=self.cost)


class ScriptModel:
    def __init__(self, decisions) -> None:
        self.decisions = list(decisions)

    async def decide(self, turn):
        return self.decisions.pop(0)


class NoopCredentialSource:
    async def issue(self, *, audience: str):
        raise AssertionError("credential source should not be called")


class NoopTransport:
    async def post_json(self, **kwargs):
        raise AssertionError("transport should not be called")


class StaticTransportSelector:
    def __init__(self) -> None:
        self.candidates: list[str] = []

    def for_candidate(self, candidate_id: str):
        self.candidates.append(candidate_id)
        return NoopTransport()


class NoopRuntimeFactory:
    def create(self, workspace: Path):
        raise AssertionError("runtime should not be created in composition-only test")


class ProviderQualificationEvaluatorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.corpus = load_provider_qualification_corpus(ROOT, CORPUS_PATH)
        cls.repair_case = cls.corpus.cases[0]
        cls.escalation_case = next(
            case for case in cls.corpus.cases if case.case_id == "escalation-003-specification-conflict"
        )

    def _runner(self, mode: str, *, clock=None, cost: str = "0.01"):
        return OracleBackedProviderQualificationCaseRunner(
            factory_repository_root=ROOT,
            candidate_factory=FakeCandidateFactory(mode, cost=cost),
            policy=ProviderQualificationEvaluatorPolicy(
                expected_provisioner_identity="qualification_provisioner_v1",
                expected_runner_identity="qualification_verifier_v1",
            ),
            clock_ns=clock or SequenceClock(0, 5_000_000),
        )

    def test_good_repair_must_pass_hidden_oracle(self):
        observation = asyncio.run(
            self._runner("good", cost="0.02").run_case(
                candidate_id="baseline",
                case=self.repair_case,
            )
        )
        self.assertTrue(observation.verified_repair)
        self.assertFalse(observation.verification_false_positive)
        self.assertFalse(observation.escalated)
        self.assertEqual(observation.policy_violations, 0)
        self.assertEqual(observation.unsafe_edit_attempts, 0)
        self.assertEqual(observation.protected_path_requests, 0)
        self.assertEqual(observation.cost_usd, Decimal("0.02"))
        self.assertEqual(observation.latency_ms, 5)

    def test_visible_false_green_is_caught_by_hidden_verification(self):
        observation = asyncio.run(
            self._runner("false-positive").run_case(
                candidate_id="bad-visible-only",
                case=self.repair_case,
            )
        )
        self.assertFalse(observation.verified_repair)
        self.assertTrue(observation.verification_false_positive)
        self.assertEqual(observation.policy_violations, 0)

    def test_functionally_correct_protected_path_attempt_is_not_verified(self):
        observation = asyncio.run(
            self._runner("unsafe-green").run_case(
                candidate_id="unsafe",
                case=self.repair_case,
            )
        )
        self.assertFalse(observation.verified_repair)
        self.assertGreater(observation.protected_path_requests, 0)
        self.assertGreater(observation.unsafe_edit_attempts, 0)
        self.assertGreater(observation.policy_violations, 0)

    def test_expected_escalation_is_recorded_without_hidden_test(self):
        observation = asyncio.run(
            self._runner("escalate").run_case(
                candidate_id="safe-escalator",
                case=self.escalation_case,
            )
        )
        self.assertTrue(observation.escalated)
        self.assertFalse(observation.verified_repair)
        self.assertFalse(observation.verification_false_positive)
        self.assertFalse(observation.execution_failure)

    def test_authoritative_workspace_mutation_is_policy_violation(self):
        observation = asyncio.run(
            self._runner("mutate-authoritative").run_case(
                candidate_id="mutator",
                case=self.repair_case,
            )
        )
        self.assertTrue(observation.escalated)
        self.assertGreater(observation.policy_violations, 0)

    def test_oracle_binding_rejects_case_mismatch(self):
        wrong = ProviderQualificationCase(
            case_id=self.repair_case.case_id,
            category=self.repair_case.category,
            expected_outcome=self.repair_case.expected_outcome,
            fixture_ref=self.repair_case.fixture_ref,
            oracle_ref="factory/evals/oracles/provider-repair-v1/repair-002-clamp-upper-bound.json",
            original_command=self.repair_case.original_command,
            protected_paths=self.repair_case.protected_paths,
            tags=self.repair_case.tags,
        )
        with self.assertRaises(ProviderQualificationError):
            load_provider_qualification_oracle(ROOT, wrong)

    def test_invalid_clock_fails_closed(self):
        with self.assertRaises(ProviderQualificationError):
            asyncio.run(
                self._runner("escalate", clock=SequenceClock(10, 9)).run_case(
                    candidate_id="clock-bug",
                    case=self.escalation_case,
                )
            )

    def test_tracing_model_records_paths_only(self):
        model = ScriptModel(
            [
                ReadFilesDecision(paths=("app.py",)),
                ApplyEditsDecision(
                    summary="fix",
                    edits=(LiteralReplaceEdit("app.py", "old", "new"),),
                ),
            ]
        )
        from factory_runtime.provider_qualification_evaluator import _TraceRecorder

        recorder = _TraceRecorder()
        tracing = TracingRepairModel(model, recorder)
        asyncio.run(tracing.decide(None))
        asyncio.run(tracing.decide(None))
        trace = recorder.snapshot()
        self.assertEqual(trace.read_paths, ("app.py",))
        self.assertEqual(trace.edit_paths, ("app.py",))

    def test_brokered_candidate_factory_selects_transport_by_candidate(self):
        from factory_runtime.provider_broker import ProviderBrokerBudget

        selector = StaticTransportSelector()
        factory = BrokeredQualificationCandidateFactory(
            factory_repository_root=ROOT,
            runtime_factory=NoopRuntimeFactory(),
            credential_source=NoopCredentialSource(),
            transport_selector=selector,
            broker_budget=ProviderBrokerBudget(
                max_cost_usd_per_call=Decimal("0.10"),
                max_total_cost_usd=Decimal("0.20"),
            ),
        )
        with tempfile.TemporaryDirectory() as tmp:
            runtime = factory.create(candidate_id="challenger-a", workspace=Path(tmp))
        self.assertEqual(selector.candidates, ["challenger-a"])
        self.assertEqual(runtime.spent_usd, Decimal("0"))
        self.assertEqual(runtime.trace, QualificationModelTrace((), (), 0))


if __name__ == "__main__":
    unittest.main()
