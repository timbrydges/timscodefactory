import sys
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import verify_acceptance_credential_stage as verifier


class CredentialStageTests(unittest.TestCase):
    def aws_fixture(self, *, stages=None, enabled='false'):
        calls = []
        secret_arn = (f'arn:aws:secretsmanager:{verifier.REGION}:{verifier.ACCOUNT}:'
                      f'secret:{verifier.SECRET}-WE57Tw')
        kms_arn = f'arn:aws:kms:{verifier.REGION}:{verifier.ACCOUNT}:key/key-1'
        broker = (f'arn:aws:lambda:{verifier.REGION}:{verifier.ACCOUNT}:'
                  f'function:{verifier.FUNCTION}:{verifier.BROKER_VERSION}')

        def aws(service, action, *args):
            calls.append((service, action))
            if action == 'get-caller-identity':
                return {'Account': verifier.ACCOUNT}
            if action == 'describe-secret':
                return {'Name': verifier.SECRET, 'ARN': secret_arn, 'KmsKeyId': kms_arn,
                        'VersionIdsToStages': stages if stages is not None else
                        {'version-1': ['AWSCURRENT']}}
            if action == 'describe-key':
                return {'KeyMetadata': {'Arn': kms_arn, 'KeyState': 'Enabled',
                                        'KeyManager': 'CUSTOMER'}}
            if action == 'get-key-rotation-status':
                return {'KeyRotationEnabled': True}
            if action == 'list-attached-role-policies':
                return {'AttachedPolicies': [
                    {'PolicyName': name, 'PolicyArn': arn} for name, arn in
                    zip(verifier.POLICY_NAMES, verifier.POLICY_ARNS)]}
            if action == 'describe-stacks':
                return {'Stacks': [{'StackStatus': 'UPDATE_COMPLETE', 'Outputs': [
                    {'OutputKey': 'BrokerVersionArn', 'OutputValue': broker}]}]}
            if action == 'get-function-configuration':
                return {'FunctionArn': args[1], 'Role':
                        f'arn:aws:iam::{verifier.ACCOUNT}:role/{verifier.ROLE}',
                        'Environment': {'Variables': dict(verifier.ENVIRONMENT,
                            FACTORY_ACCEPTANCE_BROKER_ENABLED=enabled)}, 'State': 'Active'}
            raise AssertionError(f'unexpected operation: {service} {action}')
        return aws, calls

    def test_current_version_and_disabled_broker_pass_without_secret_read(self):
        aws, calls = self.aws_fixture()
        with patch.object(verifier, 'aws', side_effect=aws), \
                patch.object(verifier, 'source', return_value='a' * 40), \
                patch.object(verifier, '_assert_policy_documents'):
            result = verifier.verify()
        self.assertEqual(result['status'], 'DISABLED_BROKER_CREDENTIAL_STAGE_VERIFIED')
        self.assertEqual(result['broker_source_commit'], verifier.COMPOSITION_COMMIT)
        self.assertFalse(result['broker_enabled'])
        self.assertNotIn(('secretsmanager', 'get-secret-value'), calls)
        self.assertNotIn(('lambda', 'invoke'), calls)

    def test_missing_current_version_fails_closed(self):
        aws, _ = self.aws_fixture(stages={'version-1': ['AWSPREVIOUS']})
        with patch.object(verifier, 'aws', side_effect=aws), \
                patch.object(verifier, 'source', return_value='a' * 40):
            with self.assertRaisesRegex(RuntimeError, 'AWSCURRENT'):
                verifier.verify()

    def test_enabled_latest_fails_closed(self):
        aws, _ = self.aws_fixture(enabled='true')
        with patch.object(verifier, 'aws', side_effect=aws), \
                patch.object(verifier, 'source', return_value='a' * 40), \
                patch.object(verifier, '_assert_policy_documents'):
            with self.assertRaisesRegex(RuntimeError, 'not disabled'):
                verifier.verify()

    def test_wrong_pinned_version_fails_closed(self):
        aws, _ = self.aws_fixture()
        def wrong_version(service, action, *args):
            result = aws(service, action, *args)
            if action == 'describe-stacks':
                result['Stacks'][0]['Outputs'][0]['OutputValue'] += '-different'
            return result
        with patch.object(verifier, 'aws', side_effect=wrong_version), \
                patch.object(verifier, 'source', return_value='a' * 40), \
                patch.object(verifier, '_assert_policy_documents'):
            with self.assertRaisesRegex(RuntimeError, 'pinned disabled broker version 4'):
                verifier.verify()


if __name__ == '__main__':
    unittest.main()
