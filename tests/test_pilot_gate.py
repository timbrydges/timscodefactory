from __future__ import annotations

import copy
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from factory_state.pilot import (  # noqa: E402
    OWNER_IDENTITY,
    PILOT_SYSTEMS,
    REQUIRED_ACTIVATION_GATES,
    PilotActivationPolicy,
    PilotGateError,
)
from scripts.pilot_gate import load_contract, simulate_current_policy, validate_contract  # noqa: E402


class PilotActivationGateTests(unittest.TestCase):
    def setUp(self):
        self.contract = load_contract(ROOT)

    def _live_contract(self):
        contract = copy.deepcopy(self.contract)
        contract["status"] = "OWNER_APPROVED_LIVE_PILOT"
        contract["execution"] = {
            "phase": "LIVE_PILOT",
            "dry_run_simulation": "ALLOW",
            "infrastructure_provisioning": "ALLOW",
            "rollback_drill": "ALLOW",
            "operational_role_activation": "ALLOW",
            "pilot_repository_writes": "ALLOW",
            "live_task_transitions": "ALLOW",
            "real_release": "ALLOW",
        }
        contract["pilot"]["repository"]["current_status"] = "ACTIVE"
        for name in REQUIRED_ACTIVATION_GATES:
            contract["activation"]["gates"][name] = {
                "verified": True,
                "evidence": [f"evidence/{name}.json"],
            }
        return contract

    def _infra_contract(self):
        contract = copy.deepcopy(self.contract)
        contract["status"] = "OWNER_APPROVED_INFRA_VERIFICATION"
        contract["execution"] = {
            "phase": "INFRA_VERIFICATION",
            "dry_run_simulation": "ALLOW",
            "infrastructure_provisioning": "ALLOW",
            "rollback_drill": "ALLOW",
            "operational_role_activation": "DENY",
            "pilot_repository_writes": "DENY",
            "live_task_transitions": "DENY",
            "real_release": "DENY",
        }
        contract["activation"]["gates"]["aws_account_verified"] = {
            "verified": True,
            "evidence": ["evidence/aws-account-verification.json"],
        }
        return contract

    def test_pg01_current_contract_is_schema_and_policy_valid(self):
        self.assertEqual(validate_contract(self.contract, ROOT), ())

    def test_pg02_current_contract_simulation_passes_without_aws(self):
        self.assertEqual(simulate_current_policy(self.contract), ())

    def test_pg03_all_operational_roles_are_blocked_during_dry_run(self):
        policy = PilotActivationPolicy.from_contract(self.contract)
        for system in PILOT_SYSTEMS:
            with self.subTest(system=system), self.assertRaises(PilotGateError):
                policy.assert_role_activation_allowed(system)

    def test_pg04_repository_writes_and_transitions_are_blocked_during_dry_run(self):
        policy = PilotActivationPolicy.from_contract(self.contract)
        with self.assertRaises(PilotGateError):
            policy.assert_repository_write_allowed()
        with self.assertRaises(PilotGateError):
            policy.assert_live_transition_allowed()

    def test_pg05_even_owner_release_is_blocked_before_readiness(self):
        policy = PilotActivationPolicy.from_contract(self.contract)
        with self.assertRaises(PilotGateError):
            policy.assert_real_release_allowed(
                actor_identity=OWNER_IDENTITY,
                inspector_evidence_verified=True,
                deterministic_ci_passed=True,
                exact_commit_binding_verified=True,
            )

    def test_pg06_live_label_with_one_missing_gate_fails_closed(self):
        contract = self._live_contract()
        contract["activation"]["gates"]["rollback_drill_verified"] = {
            "verified": False,
            "evidence": [],
        }
        with self.assertRaises(PilotGateError):
            PilotActivationPolicy.from_contract(contract)

    def test_pg07_verified_live_contract_activates_exactly_three_systems(self):
        policy = PilotActivationPolicy.from_contract(self._live_contract())
        for system in PILOT_SYSTEMS:
            policy.assert_role_activation_allowed(system)
        with self.assertRaises(PilotGateError):
            policy.assert_role_activation_allowed("release_agent")

    def test_pg08_merge_requires_inspector_ci_and_exact_commit(self):
        policy = PilotActivationPolicy.from_contract(self._live_contract())
        policy.assert_merge_allowed(
            inspector_evidence_verified=True,
            deterministic_ci_passed=True,
            exact_commit_binding_verified=True,
        )
        for values in ((False, True, True), (True, False, True), (True, True, False)):
            with self.subTest(values=values), self.assertRaises(PilotGateError):
                policy.assert_merge_allowed(
                    inspector_evidence_verified=values[0],
                    deterministic_ci_passed=values[1],
                    exact_commit_binding_verified=values[2],
                )

    def test_pg09_only_tim_can_authorize_real_release(self):
        policy = PilotActivationPolicy.from_contract(self._live_contract())
        with self.assertRaises(PilotGateError):
            policy.assert_real_release_allowed(
                actor_identity="factory_controller_service",
                inspector_evidence_verified=True,
                deterministic_ci_passed=True,
                exact_commit_binding_verified=True,
            )
        policy.assert_real_release_allowed(
            actor_identity=OWNER_IDENTITY,
            inspector_evidence_verified=True,
            deterministic_ci_passed=True,
            exact_commit_binding_verified=True,
        )

    def test_pg10_verified_gate_requires_durable_evidence_reference(self):
        contract = self._live_contract()
        contract["activation"]["gates"]["rollback_drill_verified"]["evidence"] = []
        errors = validate_contract(contract, ROOT)
        self.assertTrue(any("lacks evidence" in error for error in errors))

    def test_pg11_dry_run_allowlist_cannot_hide_real_release(self):
        contract = copy.deepcopy(self.contract)
        contract["activation"]["dry_run_allowlist"].append("real_release")
        with self.assertRaises(PilotGateError):
            PilotActivationPolicy.from_contract(contract)

    def test_pg12_owner_override_is_preserved_but_not_pilot_success_evidence(self):
        override = self.contract["activation"]["owner_override"]
        self.assertTrue(override["preserved"])
        self.assertTrue(override["must_be_audited"])
        self.assertTrue(override["disqualifies_pilot_success_until_clean_rerun"])

    def test_pg13_infrastructure_phase_allows_only_tim_to_provision(self):
        policy = PilotActivationPolicy.from_contract(self._infra_contract())
        policy.assert_infrastructure_provisioning_allowed(actor_identity=OWNER_IDENTITY)
        with self.assertRaises(PilotGateError):
            policy.assert_infrastructure_provisioning_allowed(
                actor_identity="factory_controller_service"
            )
        for system in PILOT_SYSTEMS:
            with self.subTest(system=system), self.assertRaises(PilotGateError):
                policy.assert_role_activation_allowed(system)

    def test_pg14_rollback_drill_requires_live_oidc_state_and_storage_evidence(self):
        contract = self._infra_contract()
        policy = PilotActivationPolicy.from_contract(contract)
        with self.assertRaises(PilotGateError):
            policy.assert_rollback_drill_allowed(actor_identity=OWNER_IDENTITY)
        for name in (
            "oidc_trust_verified",
            "state_store_deployed_verified",
            "release_storage_verified",
        ):
            contract["activation"]["gates"][name] = {
                "verified": True,
                "evidence": [f"evidence/{name}.json"],
            }
        PilotActivationPolicy.from_contract(contract).assert_rollback_drill_allowed(
            actor_identity=OWNER_IDENTITY
        )


if __name__ == "__main__":
    unittest.main()
