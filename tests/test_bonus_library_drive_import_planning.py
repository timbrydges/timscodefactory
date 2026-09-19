from __future__ import annotations

import json
import unittest
from pathlib import Path

import jsonschema
import yaml


ROOT = Path(__file__).resolve().parents[1]
PROJECT = ROOT / "factory/projects/bonus-library-drive-import"


class BonusLibraryDriveImportPlanningTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.contract = yaml.safe_load(
            (PROJECT / "operating-contract.yaml").read_text(encoding="utf-8")
        )
        cls.dry_run = yaml.safe_load(
            (PROJECT / "planner-dry-run.yaml").read_text(encoding="utf-8")
        )
        cls.contract_schema = json.loads(
            (ROOT / "factory/schemas/project-operating-contract.schema.json").read_text(
                encoding="utf-8"
            )
        )
        cls.architecture_schema = json.loads(
            (ROOT / "factory/schemas/project-architecture-dry-run.schema.json").read_text(
                encoding="utf-8"
            )
        )

    def test_contract_and_architecture_validate(self) -> None:
        checker = jsonschema.FormatChecker()
        jsonschema.Draft202012Validator(
            self.contract_schema, format_checker=checker
        ).validate(self.contract)
        jsonschema.Draft202012Validator(
            self.architecture_schema, format_checker=checker
        ).validate(self.dry_run)

    def test_only_planning_is_authorized(self) -> None:
        self.assertEqual(self.contract["status"], "OWNER_APPROVED_DRY_RUN_ONLY")
        self.assertEqual(self.contract["contract_version"], "0.3")
        allowed = [
            key for key, value in self.contract["execution"].items() if value == "ALLOW"
        ]
        self.assertEqual(allowed, ["contract_validation", "architecture_dry_run"])
        self.assertEqual(
            self.contract["owner_decision_required"]["decision"],
            "AUTHORIZE_SCOPE_EXPANSION",
        )

    def test_drive_identity_is_keyless_and_folder_bounded(self) -> None:
        included = " ".join(self.contract["feature_slice"]["included"])
        excluded = " ".join(self.contract["feature_slice"]["excluded"])
        constraints = " ".join(self.dry_run["constraints"])
        self.assertIn("one explicitly configured Google Drive folder", included)
        self.assertIn("service-account JSON keys", excluded)
        self.assertIn("Vercel", constraints)
        self.assertIn("OIDC", constraints)
        self.assertIn("no Google key or refresh token", constraints)

    def test_import_is_bounded_and_cannot_publish(self) -> None:
        included = " ".join(self.contract["feature_slice"]["included"])
        excluded = " ".join(self.contract["feature_slice"]["excluded"])
        self.assertIn("at most 10 files and 250 MB", included)
        self.assertIn("Automatic AI generation, approval, publication", excluded)
        self.assertEqual(self.contract["limits"]["maximum_source_bytes"], 52428800)

    def test_all_gates_and_acceptance_criteria_are_accounted_for(self) -> None:
        activation = self.contract["activation"]
        accounted = set(activation["verified_gates"]) | set(activation["pending_gates"])
        self.assertEqual(accounted, set(activation["required_gates"]))
        self.assertEqual(
            [test["id"] for test in self.contract["acceptance_tests"]],
            [f"BL-{number:02d}" for number in range(11, 21)],
        )
        self.assertEqual(
            [test["id"] for test in self.dry_run["acceptance_mapping"]],
            [f"BL-{number:02d}" for number in range(11, 21)],
        )
        self.assertIn(
            "architecture_and_threat_model_approved",
            activation["verified_gates"],
        )
        self.assertNotIn(
            "architecture_and_threat_model_approved",
            activation["pending_gates"],
        )

    def test_google_infrastructure_is_evidenced_without_overclaiming_canary(self) -> None:
        activation = self.contract["activation"]
        gate = activation["verified_gates"]["google_project_and_drive_api_approved"]
        evidence = json.loads((ROOT / gate["evidence"]).read_text(encoding="utf-8"))
        self.assertEqual(evidence["conclusion"], "provisioned_pending_runtime_canary")
        self.assertFalse(evidence["workload_identity"]["static_google_credentials_created"])
        self.assertEqual(evidence["drive_scope"]["shared_role"], "viewer")
        self.assertEqual(evidence["drive_scope"]["general_access"], "restricted")
        self.assertFalse(evidence["drive_scope"]["folder_identifier_recorded_in_public_evidence"])
        self.assertIn("keyless_workload_identity_verified", activation["pending_gates"])
        self.assertIn("drive_folder_scope_verified", activation["pending_gates"])

    def test_dry_run_stops_at_the_owner_architecture_gate(self) -> None:
        self.assertFalse(self.dry_run["authoritative"])
        self.assertEqual(
            self.dry_run["owner_decision_required"]["decision"],
            "APPROVE_ARCHITECTURE_AND_THREAT_MODEL",
        )
        self.assertIn(
            "architecture_and_threat_model_approved",
            self.dry_run["remaining_gates"],
        )


if __name__ == "__main__":
    unittest.main()
