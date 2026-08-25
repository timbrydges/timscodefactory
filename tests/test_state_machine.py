from __future__ import annotations

import sys
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from factory_state.model import (  # noqa: E402
    AuthorityError,
    Evidence,
    EvidenceError,
    FactoryStateMachine,
    InvalidTransition,
    Lease,
    LeaseError,
    StaleVersion,
    TaskState,
)


NOW = datetime.now(timezone.utc)
CONTROLLER = "factory_controller_service"


def initial(state: str = "INTAKE") -> TaskState:
    return TaskState("factory", "task-1", state, 0, NOW, CONTROLLER)


class StateTransitionContractTests(unittest.TestCase):
    def test_st01_valid_transition(self):
        machine = FactoryStateMachine(initial())
        self.assertEqual(machine.transition(CONTROLLER, "SPECIFICATION", expected_version=0).state, "SPECIFICATION")

    def test_st02_invalid_transition_defaults_deny(self):
        with self.assertRaises(InvalidTransition):
            FactoryStateMachine(initial()).transition(CONTROLLER, "RELEASED", expected_version=0)

    def test_st03_stale_version_denied(self):
        with self.assertRaises(StaleVersion):
            FactoryStateMachine(initial()).transition(CONTROLLER, "SPECIFICATION", expected_version=9)

    def test_st04_non_controller_write_denied(self):
        with self.assertRaises(AuthorityError):
            FactoryStateMachine(initial()).transition("engineering_agent_service", "SPECIFICATION", expected_version=0)

    def test_st05_pause_is_controller_controlled(self):
        machine = FactoryStateMachine(initial())
        self.assertEqual(machine.transition(CONTROLLER, "PAUSED", expected_version=0).state, "PAUSED")

    def test_st06_pause_revokes_leases(self):
        machine = FactoryStateMachine(initial())
        lease = Lease("l1", "engineering_agent", "engineering_agent_service", NOW + timedelta(hours=1))
        machine.issue_lease(CONTROLLER, lease, expected_version=0)
        machine.transition(CONTROLLER, "PAUSED", expected_version=1)
        self.assertTrue(machine.state.leases[0].revoked)

    def test_st07_paused_blocks_dispatch(self):
        with self.assertRaises(AuthorityError):
            FactoryStateMachine(initial("PAUSED")).assert_dispatch_allowed(CONTROLLER, "l1")

    def test_st08_expired_lease_denies_dispatch(self):
        machine = FactoryStateMachine(initial())
        lease = Lease("l1", "engineering_agent", "engineering_agent_service", NOW - timedelta(seconds=1))
        machine.issue_lease(CONTROLLER, lease, expected_version=0)
        with self.assertRaises(LeaseError):
            machine.assert_dispatch_allowed(CONTROLLER, "l1", now=NOW)

    def test_st09_forged_evidence_denied(self):
        machine, evidence = self._machine_with_evidence(signature=False)
        with self.assertRaises(EvidenceError):
            machine.transition(CONTROLLER, "SPEC_REVIEW", expected_version=1, evidence=[evidence], now=NOW)

    def test_st10_self_approval_denied(self):
        machine, evidence = self._machine_with_evidence(reviewer="product_spec_author_service")
        with self.assertRaises(EvidenceError):
            machine.transition(CONTROLLER, "SPEC_REVIEW", expected_version=1, evidence=[evidence], now=NOW)

    def test_st11_remediation_fields_required(self):
        with self.assertRaises(InvalidTransition):
            FactoryStateMachine(initial("SPEC_REVIEW")).transition(CONTROLLER, "REMEDIATION", expected_version=0)

    def test_st12_stall_fields_required(self):
        with self.assertRaises(InvalidTransition):
            FactoryStateMachine(initial()).transition(CONTROLLER, "STALLED", expected_version=0)

    def test_st13_evidence_replay_denied(self):
        machine, evidence = self._machine_with_evidence()
        machine.transition(CONTROLLER, "SPEC_REVIEW", expected_version=1, evidence=[evidence], now=NOW)
        with self.assertRaises(EvidenceError):
            machine.transition(CONTROLLER, "ARCHITECTURE", expected_version=2, evidence=[evidence], now=NOW)

    def test_st14_lease_id_replay_denied(self):
        machine = FactoryStateMachine(initial())
        lease = Lease("l1", "engineering_agent", "engineering_agent_service", NOW + timedelta(hours=1))
        machine.issue_lease(CONTROLLER, lease, expected_version=0)
        with self.assertRaises(LeaseError):
            machine.issue_lease(CONTROLLER, lease, expected_version=1)

    def test_st15_audit_is_append_only_view(self):
        machine = FactoryStateMachine(initial())
        machine.transition(CONTROLLER, "SPECIFICATION", expected_version=0)
        self.assertIsInstance(machine.audit, tuple)
        self.assertEqual(machine.audit[0]["to_version"], 1)

    def _machine_with_evidence(self, *, signature=True, reviewer=None):
        machine = FactoryStateMachine(initial("SPECIFICATION"))
        lease = Lease("l1", "product_spec_author", "product_spec_author_service", NOW + timedelta(hours=1))
        machine.issue_lease(CONTROLLER, lease, expected_version=0)
        evidence = Evidence("e1", "product_spec_author", "product_spec_author_service", "task-1", "l1", "abc", "sha256:abc", NOW, signature, reviewer)
        return machine, evidence


if __name__ == "__main__":
    unittest.main()

