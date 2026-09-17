from pathlib import Path
import unittest

import yaml


ROOT = Path(__file__).resolve().parents[1]
TERRAFORM = (ROOT / "infra/aws/bonus_library_identity.tf").read_text(encoding="utf-8")
WORKFLOW_PATH = ROOT / "config/github/bonus-library/identity-canary.yml"


class BonusLibraryIdentityTests(unittest.TestCase):
    def test_identity_is_bound_to_immutable_repository_and_owner(self) -> None:
        self.assertIn('bonus_library_repository          = "timbrydges/bonus-library"', TERRAFORM)
        self.assertIn('bonus_library_repository_owner_id = "214414801"', TERRAFORM)
        self.assertIn('bonus_library_repository_id       = "1375052827"', TERRAFORM)
        self.assertIn('values   = ["refs/heads/main"]', TERRAFORM)
        self.assertIn('values   = [local.bonus_library_environment]', TERRAFORM)
        self.assertIn('values   = [local.bonus_library_workflow]', TERRAFORM)
        self.assertIn('variable = "token.actions.githubusercontent.com:actor_id"', TERRAFORM)


    def test_identity_role_has_no_runtime_policy(self) -> None:
        self.assertIn('resource "aws_iam_role" "github_bonus_library_identity"', TERRAFORM)
        self.assertNotIn('resource "aws_iam_role_policy" "github_bonus_library', TERRAFORM)
        self.assertNotIn('resource "aws_iam_role_policy_attachment" "github_bonus_library', TERRAFORM)
        self.assertNotIn("bedrock:", TERRAFORM)
        self.assertNotIn("s3:", TERRAFORM)
        self.assertNotIn("dynamodb:", TERRAFORM)


    def test_canary_is_manual_owner_environment_identity_check_only(self) -> None:
        workflow = yaml.safe_load(WORKFLOW_PATH.read_text(encoding="utf-8"))
        self.assertEqual(workflow["name"], "bonus-library-identity-canary")
        self.assertEqual(workflow[True], {"workflow_dispatch": None})
        self.assertEqual(workflow["permissions"], {"contents": "read", "id-token": "write"})
        job = workflow["jobs"]["verify"]
        self.assertEqual(job["environment"], "production")
        rendered = WORKFLOW_PATH.read_text(encoding="utf-8")
        self.assertIn("aws sts get-caller-identity", rendered)
        self.assertIn("AWS_PROJECT_IDENTITY_ROLE_ARN", rendered)
        self.assertNotIn("bedrock", rendered.lower())
        self.assertNotIn("terraform", rendered.lower())


if __name__ == "__main__":
    unittest.main()
