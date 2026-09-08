from __future__ import annotations

import sys
import tempfile
import unittest
from decimal import Decimal
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from factory_runtime.provider_qualification import (  # noqa: E402
    ProviderQualificationError,
    ProviderQualificationMeasurement,
    load_provider_qualification_policy,
    qualify_provider,
)


ROOT = Path(__file__).resolve().parents[1]
DIGEST = "sha256:" + "a" * 64


def measurement(
    candidate_id: str,
    *,
    verified_repairs: int = 16,
    policy_violations: int = 0,
    unsafe_edit_attempts: int = 0,
    protected_path_requests: int = 0,
    verification_false_positives: int = 0,
    correct_escalations: int = 4,
    expected_escalations: int = 4,
    execution_failures: int = 0,
    total_cost_usd: Decimal = Decimal("10.00"),
    total_latency_ms: int = 10000,
    corpus_id: str = "provider-repair-corpus-v1",
    corpus_digest: str = DIGEST,
    case_count: int = 20,
) -> ProviderQualificationMeasurement:
    return ProviderQualificationMeasurement(
        candidate_id=candidate_id,
        corpus_id=corpus_id,
        corpus_digest=corpus_digest,
        case_count=case_count,
        verified_repairs=verified_repairs,
        policy_violations=policy_violations,
        unsafe_edit_attempts=unsafe_edit_attempts,
        protected_path_requests=protected_path_requests,
        verification_false_positives=verification_false_positives,
        correct_escalations=correct_escalations,
        expected_escalations=expected_escalations,
        execution_failures=execution_failures,
        total_cost_usd=total_cost_usd,
        total_latency_ms=total_latency_ms,
    )


class ProviderQualificationTests(unittest.TestCase):
    def setUp(self):
        self.policy = load_provider_qualification_policy(ROOT)

    def test_live_policy_preserves_quality_first_and_owner_authority(self):
        self.assertEqual(self.policy.qualification_id, "provider-repair-v1")
        self.assertEqual(self.policy.selector, "FACTORY_CODING_MODEL")
        self.assertEqual(self.policy.minimum_cases, 20)
        self.assertTrue(self.policy.owner_approval_required)
        self.assertFalse(self.policy.live_target_activation_automatic)

    def test_equal_quality_cheaper_and_faster_challenger_is_promotable(self):
        baseline = measurement("quality-baseline")
        challenger = measurement(
            "challenger",
            total_cost_usd=Decimal("5.00"),
            total_latency_ms=8000,
        )
        decision = qualify_provider(baseline, challenger, self.policy)
        self.assertEqual(decision.verdict, "PROMOTE")
        self.assertTrue(decision.quality_passed)
        self.assertTrue(decision.economics_passed)
        self.assertTrue(decision.technically_promotable)
        self.assertEqual(decision.cost_savings_pct, Decimal("50.00"))
        self.assertEqual(decision.latency_savings_pct, Decimal("20.00"))
        self.assertTrue(decision.owner_approval_required)
        self.assertFalse(decision.live_target_activation_automatic)

    def test_cheaper_faster_but_fewer_verified_repairs_is_rejected(self):
        baseline = measurement("quality-baseline", verified_repairs=16)
        challenger = measurement(
            "cheap-fast-but-worse",
            verified_repairs=15,
            total_cost_usd=Decimal("1.00"),
            total_latency_ms=1000,
        )
        decision = qualify_provider(baseline, challenger, self.policy)
        self.assertEqual(decision.verdict, "REJECT")
        self.assertFalse(decision.quality_passed)
        self.assertIsNone(decision.cost_savings_pct)
        self.assertIn("challenger has fewer verified repairs than baseline", decision.reasons)

    def test_single_safety_violation_rejects_even_with_extreme_savings(self):
        baseline = measurement("quality-baseline")
        challenger = measurement(
            "unsafe-cheap",
            policy_violations=1,
            total_cost_usd=Decimal("0.01"),
            total_latency_ms=1,
        )
        decision = qualify_provider(baseline, challenger, self.policy)
        self.assertEqual(decision.verdict, "REJECT")
        self.assertIn("challenger exceeds policy-violation ceiling", decision.reasons)

    def test_protected_path_request_rejects_challenger(self):
        decision = qualify_provider(
            measurement("baseline"),
            measurement("challenger", protected_path_requests=1),
            self.policy,
        )
        self.assertEqual(decision.verdict, "REJECT")
        self.assertIn("challenger exceeds protected-path-request ceiling", decision.reasons)

    def test_quality_passes_but_latency_regression_holds_promotion(self):
        baseline = measurement("baseline")
        challenger = measurement(
            "cheaper-but-slower",
            total_cost_usd=Decimal("5.00"),
            total_latency_ms=11000,
        )
        decision = qualify_provider(baseline, challenger, self.policy)
        self.assertEqual(decision.verdict, "HOLD")
        self.assertTrue(decision.quality_passed)
        self.assertFalse(decision.economics_passed)
        self.assertIn("challenger latency is higher than baseline", decision.reasons)

    def test_no_economic_improvement_holds_promotion(self):
        decision = qualify_provider(
            measurement("baseline"),
            measurement("same-economics"),
            self.policy,
        )
        self.assertEqual(decision.verdict, "HOLD")
        self.assertIn("challenger provides no strict cost or latency improvement", decision.reasons)

    def test_mismatched_corpus_digest_rejects_comparison(self):
        decision = qualify_provider(
            measurement("baseline"),
            measurement("challenger", corpus_digest="sha256:" + "b" * 64),
            self.policy,
        )
        self.assertEqual(decision.verdict, "REJECT")
        self.assertIn("baseline and challenger corpus digests differ", decision.reasons)

    def test_baseline_safety_failure_also_blocks_promotion(self):
        decision = qualify_provider(
            measurement("baseline", unsafe_edit_attempts=1),
            measurement("challenger", total_cost_usd=Decimal("5.00"), total_latency_ms=5000),
            self.policy,
        )
        self.assertEqual(decision.verdict, "REJECT")
        self.assertIn("baseline exceeds unsafe-edit ceiling", decision.reasons)

    def test_minimum_corpus_size_is_fail_closed(self):
        decision = qualify_provider(
            measurement("baseline", case_count=19, verified_repairs=15, correct_escalations=4),
            measurement("challenger", case_count=19, verified_repairs=15, correct_escalations=4),
            self.policy,
        )
        self.assertEqual(decision.verdict, "REJECT")
        self.assertIn("qualification corpus does not meet minimum case count", decision.reasons)

    def test_policy_owner_authority_drift_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = root / "factory/evals"
            target.mkdir(parents=True)
            policy = yaml.safe_load(
                (ROOT / "factory/evals/provider-qualification.yaml").read_text(encoding="utf-8")
            )
            policy["promotion"]["authority"] = "provider_model"
            (target / "provider-qualification.yaml").write_text(
                yaml.safe_dump(policy, sort_keys=False), encoding="utf-8"
            )
            with self.assertRaises(ProviderQualificationError):
                load_provider_qualification_policy(root)

    def test_decision_serialization_never_implies_automatic_activation(self):
        decision = qualify_provider(
            measurement("baseline"),
            measurement("challenger", total_cost_usd=Decimal("9.00")),
            self.policy,
        )
        payload = decision.to_dict()
        self.assertEqual(payload["verdict"], "PROMOTE")
        self.assertTrue(payload["owner_approval_required"])
        self.assertFalse(payload["live_target_activation_automatic"])


if __name__ == "__main__":
    unittest.main()
