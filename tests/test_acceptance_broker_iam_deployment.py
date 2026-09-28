import sys
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))

from prepare_acceptance_broker_iam import (
    ACCOUNT, POLICY_ARNS, _assert_policy_documents, validate_changes, validate_template,
)


class AcceptanceBrokerIamDeploymentTests(unittest.TestCase):
    def test_only_existing_role_can_change_in_place(self):
        accepted = [{'ResourceChange': {'LogicalResourceId': 'BrokerRole',
                                        'Action': 'Modify', 'Replacement': 'False'}}]
        validate_template()
        validate_changes(accepted)
        for bad in ([], accepted + [{'ResourceChange': {'LogicalResourceId': 'BrokerFunction',
                                                       'Action': 'Modify', 'Replacement': 'False'}}],
                    [{'ResourceChange': {**accepted[0]['ResourceChange'], 'Replacement': 'True'}}]):
            with self.subTest(bad=bad), self.assertRaises(RuntimeError):
                validate_changes(bad)

    def test_exact_policy_documents_reject_broader_secret_access(self):
        region = 'ca-central-1'
        base = f'arn:aws:dynamodb:{region}:{ACCOUNT}:table/'
        secret = (f'arn:aws:secretsmanager:{region}:{ACCOUNT}:secret:'
                  'tims-software-factory/provider/openai/acceptance-WE57Tw')
        kms = f'arn:aws:kms:{region}:{ACCOUNT}:key/key-123'
        condition = {'ForAllValues:StringLike': {'dynamodb:LeadingKeys': 'ACTIVATION#*'}}
        documents = [
            {'Version': '2012-10-17', 'Statement': [
                {'Sid': 'ReadExactAcceptanceReservations', 'Effect': 'Allow',
                 'Action': ['dynamodb:GetItem'], 'Resource': base + 'tims-factory-acceptance-budget',
                 'Condition': condition},
                {'Sid': 'ClaimExactAcceptanceDispatch', 'Effect': 'Allow',
                 'Action': ['dynamodb:UpdateItem', 'dynamodb:PutItem', 'dynamodb:GetItem'],
                 'Resource': base + 'tims-factory-acceptance-broker-claims',
                 'Condition': condition}]},
            {'Version': '2012-10-17', 'Statement': [
                {'Sid': 'ReadExactCurrentProviderSecret', 'Effect': 'Allow',
                 'Action': ['secretsmanager:GetSecretValue'], 'Resource': secret,
                 'Condition': {'ForAnyValue:StringEquals': {
                     'secretsmanager:VersionStage': 'AWSCURRENT'}}},
                {'Sid': 'DecryptOnlyThroughExactSecretsManagerRegion', 'Effect': 'Allow',
                 'Action': 'kms:Decrypt', 'Resource': kms,
                 'Condition': {'StringEquals': {
                     'kms:ViaService': 'secretsmanager.ca-central-1.amazonaws.com'}}}]}]

        def aws_stub(service, operation, *args):
            if (service, operation) == ('secretsmanager', 'describe-secret'):
                return {'Name': 'tims-software-factory/provider/openai/acceptance', 'ARN': secret}
            if (service, operation) == ('kms', 'describe-key'):
                return {'KeyMetadata': {'Arn': kms}}
            if (service, operation) == ('iam', 'get-policy'):
                arn = args[args.index('--policy-arn') + 1]
                return {'Policy': {'Arn': arn, 'AttachmentCount': 0,
                                   'DefaultVersionId': 'v1'}}
            if (service, operation) == ('iam', 'get-policy-version'):
                arn = args[args.index('--policy-arn') + 1]
                return {'PolicyVersion': {'Document': documents[POLICY_ARNS.index(arn)]}}
            raise AssertionError((service, operation, args))

        with patch('prepare_acceptance_broker_iam.aws', side_effect=aws_stub):
            _assert_policy_documents()
            documents[1]['Statement'][0]['Resource'] = '*'
            with self.assertRaisesRegex(RuntimeError, 'least privilege'):
                _assert_policy_documents()


if __name__ == '__main__':
    unittest.main()
