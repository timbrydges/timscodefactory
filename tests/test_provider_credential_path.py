from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]


class ProviderCredentialPathTests(unittest.TestCase):
    def test_terraform_prepares_secret_without_secret_value(self):
        text = (ROOT / "infra/aws/provider_credentials.tf").read_text(encoding="utf-8")
        self.assertIn('resource "aws_secretsmanager_secret" "provider_openai"', text)
        self.assertNotIn('aws_secretsmanager_secret_version', text)
        self.assertNotIn('secret_string', text.lower())
        self.assertIn('recovery_window_in_days = 30', text)
        self.assertIn('enable_key_rotation     = true', text)

    def test_reader_policy_is_exact_current_and_kms_via_service_only(self):
        text = (ROOT / "infra/aws/provider_credentials.tf").read_text(encoding="utf-8")
        self.assertIn('["secretsmanager:GetSecretValue"]', text)
        self.assertIn('resources = [aws_secretsmanager_secret.provider_openai.arn]', text)
        self.assertIn('variable = "secretsmanager:VersionStage"', text)
        self.assertIn('values   = ["AWSCURRENT"]', text)
        self.assertIn('resources = [aws_kms_key.provider_credentials.arn]', text)
        self.assertIn('variable = "kms:ViaService"', text)
        self.assertNotIn('resources = ["*"]', text)


if __name__ == "__main__":
    unittest.main()
