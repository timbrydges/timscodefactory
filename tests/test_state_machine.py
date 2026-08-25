from __future__ import annotations

import sys
import unittest
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import jsonschema
import yaml

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
    ROLE_ALLOWED_STATES,
    ROLE_IDENTITIES,
    StateError,
    StaleVersion,
    TaskState,
)
from factory_state.dynamodb import DynamoDBStateStore  # noqa: E402


NOW = datetime.now(timezone.utc)
CONTROLLER = "factory_controller_service"
OWNER = OWNER_IDENTITY
COMMIT = "a" * 40
DIGEST = "sha256:" + "b" * 64


class FakeDynamoDB:
    def __init__(self):
        self.calls = []
        self.item = None

    def transact_write_items(self, **kwargs):
        self.calls.append(kwargs)

    def get_item(self, **kwargs):
        return {} if self.item is None else {"Item": self.item}


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
        machine = FactoryStateMachine(initial("IMPLEMENTATION"))
        lease = Lease("l1", "engineering_agent", "engineering_agent_service", NOW + timedelta(hours=1))
        machine.issue_lease(CONTROLLER, lease, expected_version=0)
        machine.transition(CONTROLLER, "PAUSED", expected_version=1)
        self.assertTrue(machine.state.leases[0].revoked)

    def test_st07_paused_blocks_dispatch(self):
        with self.assertRaises(AuthorityError):
            FactoryStateMachine(initial("PAUSED")).assert_dispatch_allowed(CONTROLLER, "l1")

    def test_st08_expired_lease_is_denied_at_issuance(self):
        machine = FactoryStateMachine(initial("IMPLEMENTATION"))
        lease = Lease("l1", "engineering_agent", "engineering_agent_service", NOW - timedelta(seconds=1))
        with self.assertRaises(LeaseError):
            machine.issue_lease(CONTROLLER, lease, expected_version=0, now=NOW)

    def test_st09_forged_evidence_denied(self):
        machine, evidence = self._machine_with_evidence(signature=False)
        with self.assertRaises(EvidenceError):
            machine.transition(CONTROLLER, "SPEC_REVIEW", expected_version=1, evidence=[evidence], now=NOW)

    def test_st10_self_approval_denied(self):
        machine, evidence = self._machine_with_evidence(reviewer="product_spec_author_service")
        with self.assertRaises(EvidenceError):
            machine.transition(CONTROLLER, "SPEC_REVIEW", expected_version=1, evidence=[evidence], now=NOW)

    def test_st11_remediation_fields_required(self):
        machine = FactoryStateMachine(initial("SPEC_REVIEW"))
        evidence = self._reviewer_evidence(machine)
        with self.assertRaises(InvalidTransition):
            machine.transition(
                CONTROLLER,
                "REMEDIATION",
                expected_version=machine.state.version,
                evidence=[evidence],
                now=NOW,
            )

    def test_st12_stall_fields_required(self):
        with self.assertRaises(InvalidTransition):
            FactoryStateMachine(initial()).transition(CONTROLLER, "STALLED", expected_version=0)

    def test_st13_evidence_replay_denied(self):
        machine, evidence = self._machine_with_evidence()
        machine.transition(CONTROLLER, "SPEC_REVIEW", expected_version=1, evidence=[evidence], now=NOW)
        with self.assertRaises(EvidenceError):
            machine.transition(CONTROLLER, "ARCHITECTURE", expected_version=2, evidence=[evidence], now=NOW)

    def test_st14_lease_id_replay_denied(self):
        machine = FactoryStateMachine(initial("IMPLEMENTATION"))
        lease = Lease("l1", "engineering_agent", "engineering_agent_service", NOW + timedelta(hours=1))
        machine.issue_lease(CONTROLLER, lease, expected_version=0)
        with self.assertRaises(LeaseError):
            machine.issue_lease(CONTROLLER, lease, expected_version=1)

    def test_st15_audit_is_append_only_view(self):
        machine = FactoryStateMachine(initial())
        machine.transition(CONTROLLER, "SPECIFICATION", expected_version=0)
        self.assertIsInstance(machine.audit, tuple)
        self.assertEqual(machine.audit[0]["to_version"], 1)
        visible = machine.audit[0]
        visible["to_version"] = 999
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
        machine = FactoryStateMachine(before)
        after = machine.owner_override(
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
            audit_event=machine.last_audit_event,
        )
        self.assertEqual(len(client.calls), 1)
        event = client.calls[0]["TransactItems"][1]["Put"]["Item"]
        self.assertEqual(event["event_type"]["S"], "OWNER_OVERRIDE")
        self.assertIn("Owner emergency stop", event["details"]["S"])

    def test_st24_agent_cannot_persist_authoritative_state(self):
        before = initial("IMPLEMENTATION")
        machine = FactoryStateMachine(before)
        after = machine.owner_override(
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
                audit_event=machine.last_audit_event,
            )

    def test_st25_gate_transition_requires_evidence(self):
        with self.assertRaises(EvidenceError):
            FactoryStateMachine(initial("SPECIFICATION")).transition(
                CONTROLLER,
                "SPEC_REVIEW",
                expected_version=0,
                now=NOW,
            )

    def test_st26_entire_release_path_cannot_advance_without_evidence(self):
        machine = FactoryStateMachine(initial())
        machine.transition(CONTROLLER, "SPECIFICATION", expected_version=0)
        with self.assertRaises(EvidenceError):
            machine.transition(CONTROLLER, "SPEC_REVIEW", expected_version=1, now=NOW)
        self.assertEqual(machine.state.state, "SPECIFICATION")

    def test_st27_empty_commit_or_digest_is_rejected(self):
        machine, evidence = self._machine_with_evidence()
        invalid = Evidence(
            evidence.evidence_id,
            evidence.producer_role,
            evidence.producer_identity,
            evidence.task_id,
            evidence.lease_id,
            "",
            "",
            evidence.created_at,
            True,
        )
        with self.assertRaises(EvidenceError):
            machine.transition(
                CONTROLLER,
                "SPEC_REVIEW",
                expected_version=1,
                evidence=[invalid],
                now=NOW,
            )

    def test_st28_unknown_or_wrong_state_role_lease_is_rejected(self):
        machine = FactoryStateMachine(initial("SPECIFICATION"))
        with self.assertRaises(LeaseError):
            machine.issue_lease(
                CONTROLLER,
                Lease("l1", "rogue_admin", "rogue", NOW + timedelta(hours=1)),
                expected_version=0,
                now=NOW,
            )
        with self.assertRaises(LeaseError):
            machine.issue_lease(
                CONTROLLER,
                Lease("l2", "engineering_agent", "engineering_agent_service", NOW + timedelta(hours=1)),
                expected_version=0,
                now=NOW,
            )

    def test_st29_transition_rejects_duplicate_evidence_in_one_request(self):
        machine, evidence = self._machine_with_evidence()
        with self.assertRaises(EvidenceError):
            machine.transition(
                CONTROLLER,
                "SPEC_REVIEW",
                expected_version=1,
                evidence=[evidence, evidence],
                now=NOW,
            )

    def test_st30_state_payload_cannot_be_mutated_through_input_or_property(self):
        remediation = {
            "return_state": "IMPLEMENTATION",
            "required_actions": ["fix"],
            "failure_code": "X",
        }
        machine = FactoryStateMachine(initial("SPEC_REVIEW"))
        evidence = self._reviewer_evidence(machine)
        machine.transition(
            CONTROLLER,
            "REMEDIATION",
            expected_version=machine.state.version,
            remediation=remediation,
            evidence=[evidence],
            now=NOW,
        )
        remediation["failure_code"] = "TAMPERED"
        visible = machine.state
        visible.remediation["failure_code"] = "ALSO_TAMPERED"
        self.assertEqual(machine.state.remediation["failure_code"], "X")

    def test_st31_serialized_state_matches_schema_and_round_trips(self):
        machine, evidence = self._machine_with_evidence()
        machine.transition(
            CONTROLLER,
            "SPEC_REVIEW",
            expected_version=1,
            evidence=[evidence],
            now=NOW,
        )
        state = machine.state
        item = DynamoDBStateStore._serialize_state(state)
        payload = json.loads(item["payload"]["S"])
        schema = json.loads(
            (Path(__file__).resolve().parents[1] / "factory/state/task-state.schema.json").read_text(encoding="utf-8")
        )
        jsonschema.Draft202012Validator(schema).validate(payload)
        self.assertEqual(DynamoDBStateStore._deserialize_payload(item["payload"]["S"]), state)

    def test_st32_lease_record_and_state_are_persisted_atomically(self):
        before = initial("IMPLEMENTATION")
        machine = FactoryStateMachine(before)
        after = machine.issue_lease(
            CONTROLLER,
            Lease("lease-1", "engineering_agent", "engineering_agent_service", NOW + timedelta(hours=1)),
            expected_version=0,
            now=NOW,
        )
        client = FakeDynamoDB()
        DynamoDBStateStore("factory-state", client).persist_transition(
            before,
            after,
            caller_identity=CONTROLLER,
            event_id="lease-event-1",
            audit_event=machine.last_audit_event,
        )
        transaction = client.calls[0]["TransactItems"]
        self.assertEqual(len(transaction), 3)
        lease_item = transaction[2]["Put"]["Item"]
        self.assertEqual(lease_item["SK"]["S"], "LEASE#lease-1")
        self.assertIn("N", lease_item["expires_at"])

    def test_st33_persistence_rejects_forged_version_or_audit(self):
        before = initial()
        machine = FactoryStateMachine(before)
        after = machine.transition(CONTROLLER, "SPECIFICATION", expected_version=0)
        forged = TaskState(
            after.factory_id,
            after.task_id,
            after.state,
            9,
            after.updated_at,
            after.updated_by,
        )
        with self.assertRaises(StateError):
            DynamoDBStateStore("factory-state", FakeDynamoDB()).persist_transition(
                before,
                forged,
                caller_identity=CONTROLLER,
                event_id="forged-event",
                audit_event=machine.last_audit_event,
            )

    def test_st34_pause_persists_lease_revocation_in_same_transaction(self):
        machine = FactoryStateMachine(initial("IMPLEMENTATION"))
        machine.issue_lease(
            CONTROLLER,
            Lease("lease-1", "engineering_agent", "engineering_agent_service", NOW + timedelta(hours=1)),
            expected_version=0,
            now=NOW,
        )
        before_pause = machine.state
        after_pause = machine.transition(CONTROLLER, "PAUSED", expected_version=1, now=NOW)
        client = FakeDynamoDB()
        DynamoDBStateStore("factory-state", client).persist_transition(
            before_pause,
            after_pause,
            caller_identity=CONTROLLER,
            event_id="pause-event-1",
            audit_event=machine.last_audit_event,
        )
        transaction = client.calls[0]["TransactItems"]
        self.assertEqual(len(transaction), 3)
        revoke = transaction[2]["Update"]
        self.assertEqual(revoke["Key"]["SK"]["S"], "LEASE#lease-1")
        self.assertTrue(revoke["ExpressionAttributeValues"][":revoked"]["BOOL"])

    def test_st35_controller_cannot_forge_owner_override_event_type(self):
        before = initial()
        machine = FactoryStateMachine(before)
        after = machine.transition(CONTROLLER, "SPECIFICATION", expected_version=0)
        forged_event = machine.last_audit_event
        forged_event["event_type"] = "OWNER_OVERRIDE"
        forged_event["details"] = {"reason": "forged"}
        with self.assertRaises(StateError):
            DynamoDBStateStore("factory-state", FakeDynamoDB()).persist_transition(
                before,
                after,
                caller_identity=CONTROLLER,
                event_id="forged-owner-event",
                audit_event=forged_event,
            )

    def test_st36_persistence_rechecks_controller_state_graph(self):
        before = initial()
        after = TaskState(
            before.factory_id,
            before.task_id,
            "RELEASED",
            1,
            NOW,
            CONTROLLER,
        )
        forged_event = {
            "event_type": "STATE_TRANSITION",
            "task_id": after.task_id,
            "from_version": 0,
            "to_version": 1,
            "state": "RELEASED",
            "actor_identity": CONTROLLER,
            "at": NOW.isoformat(),
            "details": {"evidence_ids": []},
        }
        with self.assertRaises(StateError):
            DynamoDBStateStore("factory-state", FakeDynamoDB()).persist_transition(
                before,
                after,
                caller_identity=CONTROLLER,
                event_id="forged-jump",
                audit_event=forged_event,
            )

    def test_st37_audit_evidence_ids_must_match_persisted_consumption(self):
        before = initial()
        after = TaskState(
            before.factory_id,
            before.task_id,
            "SPECIFICATION",
            1,
            NOW,
            CONTROLLER,
            consumed_evidence_ids=frozenset({"unreported-evidence"}),
        )
        forged_event = {
            "event_type": "STATE_TRANSITION",
            "task_id": after.task_id,
            "from_version": 0,
            "to_version": 1,
            "state": "SPECIFICATION",
            "actor_identity": CONTROLLER,
            "at": NOW.isoformat(),
            "details": {"evidence_ids": []},
        }
        with self.assertRaises(StateError):
            DynamoDBStateStore("factory-state", FakeDynamoDB()).persist_transition(
                before,
                after,
                caller_identity=CONTROLLER,
                event_id="hidden-evidence",
                audit_event=forged_event,
            )

    def test_st38_state_change_revokes_delegated_lease(self):
        machine = FactoryStateMachine(initial("IMPLEMENTATION"))
        machine.issue_lease(
            CONTROLLER,
            Lease("engineering-lease", "engineering_agent", "engineering_agent_service", NOW + timedelta(hours=1)),
            expected_version=0,
            now=NOW,
        )
        evidence = Evidence(
            "engineering-evidence",
            "engineering_agent",
            "engineering_agent_service",
            "task-1",
            "engineering-lease",
            COMMIT,
            DIGEST,
            NOW,
            True,
            "independent_inspector_service",
        )
        machine.transition(
            CONTROLLER,
            "INSPECTION",
            expected_version=1,
            evidence=[evidence],
            now=NOW,
        )
        self.assertTrue(machine.state.leases[0].revoked)

    def test_st39_remediation_can_return_only_to_recorded_state(self):
        remediation = {
            "return_state": "IMPLEMENTATION",
            "required_actions": ["correct implementation"],
            "failure_code": "INSPECTION_FAILED",
        }
        state = TaskState(
            "factory",
            "task-1",
            "REMEDIATION",
            0,
            NOW,
            CONTROLLER,
            remediation=remediation,
        )
        machine = FactoryStateMachine(state)
        machine.issue_lease(
            CONTROLLER,
            Lease("remediation-lease", "engineering_agent", "engineering_agent_service", NOW + timedelta(hours=1)),
            expected_version=0,
            now=NOW,
        )
        evidence = Evidence(
            "remediation-evidence",
            "engineering_agent",
            "engineering_agent_service",
            "task-1",
            "remediation-lease",
            COMMIT,
            DIGEST,
            NOW,
            True,
        )
        with self.assertRaises(InvalidTransition):
            machine.transition(
                CONTROLLER,
                "QA",
                expected_version=1,
                evidence=[evidence],
                now=NOW,
            )

    def test_st40_runtime_role_bindings_match_machine_contracts(self):
        roles = {}
        role_dir = Path(__file__).resolve().parents[1] / "factory/roles"
        for path in role_dir.glob("*.yaml"):
            role = yaml.safe_load(path.read_text(encoding="utf-8"))
            roles[role["role_id"]] = role
        self.assertEqual(set(ROLE_IDENTITIES), set(ROLE_ALLOWED_STATES))
        for role_id, identity in ROLE_IDENTITIES.items():
            self.assertEqual(
                roles[role_id]["identity_constraints"]["authoritative_identity"],
                identity,
            )
            self.assertEqual(set(roles[role_id]["allowed_states"]), ROLE_ALLOWED_STATES[role_id])

    def _machine_with_evidence(self, *, signature=True, reviewer=None):
        machine = FactoryStateMachine(initial("SPECIFICATION"))
        lease = Lease("l1", "product_spec_author", "product_spec_author_service", NOW + timedelta(hours=1))
        machine.issue_lease(CONTROLLER, lease, expected_version=0, now=NOW)
        evidence = Evidence("e1", "product_spec_author", "product_spec_author_service", "task-1", "l1", COMMIT, DIGEST, NOW, signature, reviewer)
        return machine, evidence

    def _reviewer_evidence(self, machine):
        lease = Lease(
            "review-lease",
            "product_spec_reviewer",
            "product_spec_reviewer_service",
            NOW + timedelta(hours=1),
        )
        machine.issue_lease(CONTROLLER, lease, expected_version=machine.state.version, now=NOW)
        return Evidence(
            "review-evidence",
            "product_spec_reviewer",
            "product_spec_reviewer_service",
            "task-1",
            "review-lease",
            COMMIT,
            DIGEST,
            NOW,
            True,
            "product_spec_author_service",
        )


if __name__ == "__main__":
    unittest.main()
