"""Replacement pickup, not key issuance: all secret-store responses are fake."""
import asyncio
from unittest import TestCase
from unittest.mock import Mock
from factory_runtime.provider_credentials import SecretsManagerProviderCredentialLeaseSource, ProviderCredentialLeaseError
from test_openai_provider import TARGET


class RotationPickupTests(TestCase):
    def setUp(self):
        self.arn = 'arn:aws:secretsmanager:ca-central-1:123456789012:secret:tims-software-factory/provider/openai/acceptance-AbCd12'
        self.client = Mock()
        self.source = SecretsManagerProviderCredentialLeaseSource(self.client, self.arn)

    def secret(self, token):
        return {'ARN': self.arn, 'Name': 'tims-software-factory/provider/openai/acceptance',
                'VersionStages': ['AWSCURRENT'], 'SecretString': token}

    def test_next_issue_reads_replacement_without_cached_old_key(self):
        self.client.get_secret_value.side_effect = [
            self.secret('fake-old-key-12345678'), self.secret('fake-new-key-12345678')]
        first = asyncio.run(self.source.issue(target=TARGET))
        second = asyncio.run(self.source.issue(target=TARGET))
        self.assertNotEqual(first.token, second.token)
        self.assertEqual(self.client.get_secret_value.call_count, 2)
        self.client.get_secret_value.assert_called_with(SecretId=self.arn, VersionStage='AWSCURRENT')
        self.assertNotIn(second.token, repr(second))

    def test_rotation_failure_does_not_fall_back_or_retry(self):
        self.client.get_secret_value.side_effect = [self.secret('fake-old-key-12345678'), RuntimeError()]
        asyncio.run(self.source.issue(target=TARGET))
        with self.assertRaises(ProviderCredentialLeaseError):
            asyncio.run(self.source.issue(target=TARGET))
        self.assertEqual(self.client.get_secret_value.call_count, 2)
