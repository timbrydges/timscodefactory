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
    OWNER_IDENTITY,
    StaleVersion,
    TaskState,
)
from factory_state.dynamodb import DynamoDBStateStore  # noqa: E402


NOW = datetime.now(timezone.utc)
CONTROLLER = "factory_controller_service"
OWNER = OWNER_IDENTITY


class FakeDynamoDB:
    def __init__(self):
        self.calls = []

    def transact_write_items(self, **kwargs):
        self.calls.append(kwargs)


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

    def test_st04_non_authoritative_write_denied(self):
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

    def test_st16_owner_may_approve_own_change_by_override(self):
        machine = FactoryStateMachine(initial("IMPLEMENTATION"))
        result = machine.owner_override(
            OWNER,
            "RELEASE_READY",
            expected_version=0,
            reason="Owner approves this change",
        )
        self.assertEqual(result.state, "RELEASE_READY")
        self.assertEqual(result.updated_by, OWNER)
        self.assertEqual(machine.audit[0]["event_type"], "OWNER_OVERRIDE")

    def test_st17_owner_can_pause_any_stage_and_revoke_leases(self):
        machine = FactoryStateMachine(initial("IMPLEMENTATION"))
        lease = Lease("l1", "engineering_agent", "engineering_agent_service", NOW + timedelta(hours=1))
        machine.issue_lease(CONTROLLER, lease, expected_version=0)
        machine.owner_override(OWNER, "PAUSED", expected_version=1, reason="Owner stop order")
        self.assertTrue(machine.state.leases[0].revoked)

    def test_st18_owner_can_resume_to_any_stage(self):
        machine = FactoryStateMachine(initial("PAUSED"))
        result = machine.owner_override(
            OWNER,
            "IMPLEMENTATION",
            expected_version=0,
            reason="Owner resumes implementation",
        )
        self.assertEqual(result.state, "IMPLEMENTATION")

    def test_st19_owner_can_dispatch_without_a_lease(self):
        FactoryStateMachine(initial("RELEASE_READY")).assert_dispatch_allowed(OWNER, "no-owner-lease")

    def test_st20_paused_blocks_every_dispatch_until_owner_resumes(self):
        with self.assertRaises(AuthorityError):
            FactoryStateMachine(initial("PAUSED")).assert_dispatch_allowed(OWNER, "no-owner-lease")

    def test_st21_non_owner_cannot_issue_owner_override(self):
        with self.assertRaises(AuthorityError):
            FactoryStateMachine(initial()).owner_override(
                CONTROLLER,
                "RELEASED",
                expected_version=0,
                reason="invalid",
            )

    def test_st22_owner_override_is_always_audited(self):
        with self.assertRaises(InvalidTransition):
            FactoryStateMachine(initial()).owner_override(
                OWNER,
                "PAUSED",
                expected_version=0,
                reason="",
            )

    def test_st23_owner_can_persist_authoritative_override(self):
        before = initial("IMPLEMENTATION")
        after = FactoryStateMachine(before).owner_override(
            OWNER,
            "PAUSED",
            expected_version=0,
            reason="Owner emergency stop",
        )
        client = FakeDynamoDB()
        DynamoDBStateStore("factory-state", client).persist_transition(
            before,
            after,
            caller_identity=OWNER,
            event_id="owner-event-1",
        )
        self.assertEqual(len(client.calls), 1)

    def test_st24_agent_cannot_persist_authoritative_state(self):
        before = initial("IMPLEMENTATION")
        after = FactoryStateMachine(before).owner_override(
            OWNER,
            "PAUSED",
            expected_version=0,
            reason="Owner emergency stop",
        )
        with self.assertRaises(AuthorityError):
            DynamoDBStateStore("factory-state", FakeDynamoDB()).persist_transition(
                before,
                after,
                caller_identity="engineering_agent_service",
                event_id="forged-event",
            )

    def _machine_with_evidence(self, *, signature=True, reviewer=None):
        machine = FactoryStateMachine(initial("SPECIFICATION"))
        lease = Lease("l1", "product_spec_author", "product_spec_author_service", NOW + timedelta(hours=1))
        machine.issue_lease(CONTROLLER, lease, expected_version=0)
        evidence = Evidence("e1", "product_spec_author", "product_spec_author_service", "task-1", "l1", "abc", "sha256:abc", NOW, signature, reviewer)
        return machine, evidence


if __name__ == "__main__":
    unittest.main()
