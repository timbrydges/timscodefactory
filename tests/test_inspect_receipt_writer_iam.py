import json
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import inspect_receipt_writer_iam as inspector


class ReceiptWriterIdentityTests(unittest.TestCase):
    def fixture(self, *, wrong_trust=False, attached=False, exact_attached=False):
        template = json.loads(inspector.TEMPLATE.read_text())

        def aws(service, action, *args):
            if action == 'get-caller-identity':
                return {'Account': inspector.ACCOUNT}
            if action == 'describe-stacks':
                return {'Stacks': [{'StackStatus': 'UPDATE_COMPLETE', 'Parameters': [
                    {'ParameterKey': 'EnableRoleExecutionTrust', 'ParameterValue': 'false'}]}]}
            if action == 'get-template':
                return {'TemplateBody': template}
            if action == 'describe-stack-resources':
                return {'StackResources': [
                    {'LogicalResourceId': logical, 'PhysicalResourceId': name}
                    for logical, name, _ in inspector.ROLES.values()]}
            role = next(kind for kind, (_, name, policy) in inspector.ROLES.items()
                        if any(name in arg or policy in arg for arg in args))
            logical, name, policy_name = inspector.ROLES[role]
            if action == 'get-role':
                trust = template['Resources'][logical]['Properties']['AssumeRolePolicyDocument']
                if wrong_trust and role == 'reviewer':
                    trust = {'Statement': [{'Effect': 'Allow', 'Action': 'sts:AssumeRole',
                                             'Principal': {'AWS': '*'}}]}
                else:
                    trust = {'Statement': [trust['Statement'][0]]}
                return {'Role': {'Arn': f'arn:aws:iam::{inspector.ACCOUNT}:role/{name}',
                                 'AssumeRolePolicyDocument': trust}}
            if action == 'list-attached-role-policies':
                if exact_attached:
                    return {'AttachedPolicies': [{'PolicyName': policy_name,
                        'PolicyArn': f'arn:aws:iam::{inspector.ACCOUNT}:policy/{policy_name}'}]}
                return {'AttachedPolicies': [{'PolicyName': 'other'}] if attached else []}
            if action == 'list-role-policies':
                return {'PolicyNames': ['OwnSigningKeyOnly']}
            if action == 'get-policy':
                return {'Policy': {'Arn': args[1], 'DefaultVersionId': 'v1',
                                   'AttachmentCount': int(exact_attached)}}
            if action == 'get-policy-version':
                return {'PolicyVersion': {'Document': {'Version': '2012-10-17',
                    'Statement': [{'Sid': 'WriteOwnerReceiptOnly' if role == 'owner' else
                                   'WriteReviewerReceiptOnly', 'Effect': 'Allow',
                                   'Action': 's3:PutObject',
                                   'Resource': f'arn:aws:s3:::{inspector.BUCKET}/'
                                       f'factory-scope-receipts/*/{role}.json',
                                   'Condition': {'StringEquals': {
                                       's3:x-amz-server-side-encryption': 'AES256'}}}]}}}
            raise AssertionError((service, action, args))
        return aws

    def test_exact_separate_roles_and_unattached_policies_pass(self):
        with patch.object(inspector, 'aws', side_effect=self.fixture()):
            result = inspector.inspect()
        self.assertEqual(result['status'],
                         'RECEIPT_WRITER_IDENTITIES_READY_FOR_REVIEW_NOT_ATTACHED')
        self.assertEqual(set(result['identities']), {'owner', 'reviewer'})
        self.assertEqual(result['receipts_published'], 0)

    def test_unexpected_reviewer_trust_fails(self):
        with patch.object(inspector, 'aws', side_effect=self.fixture(wrong_trust=True)):
            with self.assertRaisesRegex(RuntimeError, 'reviewer signing role trust differs'):
                inspector.inspect()

    def test_existing_attachment_fails(self):
        with patch.object(inspector, 'aws', side_effect=self.fixture(attached=True)):
            with self.assertRaisesRegex(RuntimeError, 'unexpected policy attachments'):
                inspector.inspect()

    def test_exact_post_attachment_verification(self):
        with patch.object(inspector, 'aws', side_effect=self.fixture(exact_attached=True)):
            result = inspector.inspect(expected_attached=True)
        self.assertEqual(result['status'], 'RECEIPT_WRITER_IAM_ATTACHED_VERIFIED')


if __name__ == '__main__':
    unittest.main()
