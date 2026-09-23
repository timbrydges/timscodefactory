from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]


class AutonomyScheduleDeploymentTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.terraform = (ROOT / "infra/aws/autonomy_schedule.tf").read_text(encoding="utf-8")
        cls.canary = (ROOT / "scripts/verify_disabled_autonomy_schedule.py").read_text(
            encoding="utf-8"
        )

    def test_schedule_is_opt_in_but_always_created_disabled(self):
        self.assertIn('variable "deploy_disabled_autonomy_schedule"', self.terraform)
        self.assertIn("default     = false", self.terraform)
        self.assertIn('state                        = "DISABLED"', self.terraform)
        self.assertNotIn('state                        = "ENABLED"', self.terraform)

    def test_scheduler_can_invoke_only_exact_acceptance_alias(self):
        self.assertIn('actions   = ["lambda:InvokeFunction"]', self.terraform)
        self.assertIn("resources = [local.autonomy_target_arn]", self.terraform)
        self.assertIn(":function:tims-software-factory-autonomy-controller:acceptance", self.terraform)
        self.assertIn('variable = "aws:SourceArn"', self.terraform)
        self.assertNotIn('resources = ["*"]', self.terraform)

    def test_schedule_payload_and_delivery_are_bounded(self):
        self.assertIn('schedule_expression          = "rate(15 minutes)"', self.terraform)
        self.assertIn('maximum_retry_attempts       = 0', self.terraform)
        self.assertIn('maximum_event_age_in_seconds = 60', self.terraform)
        self.assertIn('task_id    = "deterministic-text-fingerprint"', self.terraform)

    def test_canary_is_read_only_and_requires_disabled_state(self):
        self.assertIn('"aws", "scheduler", "get-schedule"', self.canary)
        self.assertIn('schedule.get("State") == "DISABLED"', self.canary)
        for mutating_action in ("create-schedule", "update-schedule", "delete-schedule"):
            self.assertNotIn(mutating_action, self.canary)


if __name__ == "__main__":
    unittest.main()
