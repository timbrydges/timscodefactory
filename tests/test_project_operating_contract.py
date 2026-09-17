from __future__ import annotations

import json
import unittest
from pathlib import Path

import jsonschema
import yaml


ROOT = Path(__file__).resolve().parents[1]
CONTRACT_PATH = ROOT / "factory/projects/bonus-library-importer/operating-contract.yaml"
SCHEMA_PATH = ROOT / "factory/schemas/project-operating-contract.schema.json"


class ProjectOperatingContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.contract = yaml.safe_load(CONTRACT_PATH.read_text(encoding="utf-8"))
        cls.schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))

    def test_contract_validates(self):
        jsonschema.Draft202012Validator(self.schema).validate(self.contract)

    def test_owner_approved_contract_allows_only_architecture_dry_run(self):
        self.assertEqual(self.contract["status"], "OWNER_APPROVED_DRY_RUN_ONLY")
        self.assertEqual(self.contract["approval"]["approved_on"], "2026-09-17")
        self.assertEqual(self.contract["activation"]["default"], "DENY")
        allowed = [key for key, value in self.contract["execution"].items() if value == "ALLOW"]
        self.assertEqual(allowed, ["contract_validation", "architecture_dry_run"])

    def test_owner_and_budget_bounds_are_exact(self):
        self.assertEqual(self.contract["release"]["authority_identity"], "tim_brydges")
        self.assertEqual(self.contract["release"]["other_release_authorities"], [])
        self.assertEqual(self.contract["limits"]["hard_stop_spend"], 10.0)
        self.assertEqual(self.contract["limits"]["maximum_provider_dispatches"], 3)
        self.assertEqual(self.contract["limits"]["maximum_remediation_cycles"], 2)

    def test_private_single_item_boundary_is_explicit(self):
        self.assertEqual(self.contract["repository"]["visibility"], "private")
        self.assertEqual(
            self.contract["feature_slice"]["name"], "private_single_bonus_ingestion"
        )
        excluded = " ".join(self.contract["feature_slice"]["excluded"])
        self.assertIn("Google Drive synchronization", excluded)
        self.assertIn("bulk import", excluded)
        self.assertIn("public uploads", excluded)

    def test_all_required_gates_are_accounted_for(self):
        activation = self.contract["activation"]
        accounted = set(activation["verified_gates"]) | set(activation["pending_gates"])
        self.assertEqual(accounted, set(activation["required_gates"]))
        self.assertNotIn("provider_budget_controls_verified", activation["pending_gates"])

    def test_acceptance_ids_are_unique_and_complete(self):
        acceptance = self.contract["acceptance_tests"]
        self.assertEqual([item["id"] for item in acceptance], [f"BL-{i:02d}" for i in range(1, 11)])


if __name__ == "__main__":
    unittest.main()
