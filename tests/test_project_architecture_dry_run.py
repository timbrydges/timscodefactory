from __future__ import annotations

import json
import unittest
from pathlib import Path

import jsonschema
import yaml


ROOT = Path(__file__).resolve().parents[1]
FACTORY = ROOT / "factory"
CONTRACT = yaml.safe_load(
    (FACTORY / "projects/bonus-library-importer/operating-contract.yaml").read_text(encoding="utf-8")
)
DRY_RUN = yaml.safe_load(
    (FACTORY / "projects/bonus-library-importer/planner-dry-run.yaml").read_text(encoding="utf-8")
)
SCHEMA = json.loads(
    (FACTORY / "schemas/project-architecture-dry-run.schema.json").read_text(encoding="utf-8")
)


class ProjectArchitectureDryRunTests(unittest.TestCase):
    def test_schema_and_instance_are_valid(self) -> None:
        jsonschema.Draft202012Validator.check_schema(SCHEMA)
        jsonschema.Draft202012Validator(
            SCHEMA, format_checker=jsonschema.FormatChecker()
        ).validate(DRY_RUN)

    def test_dry_run_is_non_authoritative_and_stops_at_owner_gate(self) -> None:
        self.assertFalse(DRY_RUN["authoritative"])
        self.assertEqual(DRY_RUN["status"], "NON_AUTHORITATIVE_DRY_RUN_COMPLETE")
        self.assertEqual(
            DRY_RUN["owner_decision_required"]["decision"],
            "APPROVE_ARCHITECTURE_AND_THREAT_MODEL",
        )
        self.assertIn("architecture_and_threat_model_approved", DRY_RUN["remaining_gates"])
        self.assertIn("implementation", DRY_RUN["owner_decision_required"]["effect"])

    def test_contract_records_owner_approval_and_keeps_activation_denials(self) -> None:
        execution = CONTRACT["execution"]
        for action in (
            "repository_creation",
            "infrastructure_changes",
            "operational_role_activation",
            "live_provider_calls",
            "release",
        ):
            self.assertEqual(execution[action], "DENY")
        self.assertIn(
            "architecture_and_threat_model_approved",
            CONTRACT["activation"]["verified_gates"],
        )
        self.assertNotIn(
            "architecture_and_threat_model_approved",
            CONTRACT["activation"]["pending_gates"],
        )

    def test_every_acceptance_test_is_mapped_once(self) -> None:
        expected = [item["id"] for item in CONTRACT["acceptance_tests"]]
        actual = [item["id"] for item in DRY_RUN["acceptance_mapping"]]
        self.assertEqual(actual, expected)
        self.assertEqual(len(actual), len(set(actual)))

    def test_security_and_governance_components_are_explicit(self) -> None:
        component_ids = {item["id"] for item in DRY_RUN["components"]}
        self.assertTrue(
            {
                "authentication_boundary",
                "quarantine_validator",
                "private_object_storage",
                "provider_budget_broker",
                "append_only_audit_log",
            }.issubset(component_ids)
        )
        threat_ids = {item["id"] for item in DRY_RUN["threats"]}
        self.assertEqual(threat_ids, {f"T{number:02d}" for number in range(1, 13)})


if __name__ == "__main__":
    unittest.main()
