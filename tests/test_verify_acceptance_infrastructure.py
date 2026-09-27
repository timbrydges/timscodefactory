import sys
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import verify_acceptance_infrastructure as verifier


class InfrastructureVerifierTests(unittest.TestCase):
    def test_empty_secret_and_unattached_policies_pass_without_reading_secret_value(self):
        calls = []

        def aws(service, action, *args):
            calls.append((service, action))
            if action == 'get-caller-identity':
                return {'Account': verifier.ACCOUNT}
            if action == 'describe-table':
                return {'Table': {'TableName': args[1], 'TableStatus': 'ACTIVE',
                                  'DeletionProtectionEnabled': True,
                                  'SSEDescription': {'Status': 'ENABLED'}}}
            if action == 'describe-continuous-backups':
                return {'ContinuousBackupsDescription': {'PointInTimeRecoveryDescription': {
                    'PointInTimeRecoveryStatus': 'ENABLED'}}}
            if action == 'describe-secret':
                return {'Name': verifier.SECRET, 'KmsKeyId': 'arn:aws:kms:ca-central-1:' +
                        verifier.ACCOUNT + ':key/key-1', 'VersionIdsToStages': {}}
            if action == 'describe-key':
                return {'KeyMetadata': {'Arn': args[1], 'KeyId': 'key-1',
                                        'KeyState': 'Enabled', 'KeyManager': 'CUSTOMER'}}
            if action == 'get-key-rotation-status':
                return {'KeyRotationEnabled': True}
            if action == 'list-aliases':
                return {'Aliases': [{'AliasName': verifier.ALIAS, 'TargetKeyId': 'key-1'}]}
            if action == 'get-policy':
                return {'Policy': {'Arn': args[1], 'AttachmentCount': 0}}
            if action == 'list-entities-for-policy':
                return {'PolicyGroups': [], 'PolicyRoles': [], 'PolicyUsers': []}
            raise AssertionError('unexpected AWS operation')

        with patch.object(verifier, 'aws', side_effect=aws), \
                patch.object(verifier, 'source', return_value='a' * 40):
            result = verifier.verify()
        self.assertEqual(result['provider_secret_versions'], 0)
        self.assertEqual(len(result['unattached_policies']), 5)
        self.assertNotIn(('secretsmanager', 'get-secret-value'), calls)

    def test_existing_secret_value_is_rejected_before_policy_checks(self):
        def aws(service, action, *args):
            if action == 'get-caller-identity':
                return {'Account': verifier.ACCOUNT}
            if action == 'describe-table':
                return {'Table': {'TableName': args[1], 'TableStatus': 'ACTIVE',
                                  'DeletionProtectionEnabled': True,
                                  'SSEDescription': {'Status': 'ENABLED'}}}
            if action == 'describe-continuous-backups':
                return {'ContinuousBackupsDescription': {'PointInTimeRecoveryDescription': {
                    'PointInTimeRecoveryStatus': 'ENABLED'}}}
            if action == 'describe-secret':
                return {'Name': verifier.SECRET,
                        'VersionIdsToStages': {'version': ['AWSCURRENT']}}
            raise AssertionError('secret version must stop verification')

        with patch.object(verifier, 'aws', side_effect=aws), \
                patch.object(verifier, 'source', return_value='a' * 40):
            with self.assertRaisesRegex(RuntimeError, 'versioned'):
                verifier.verify()


if __name__ == '__main__':
    unittest.main()
