"""The proposed role can reach only one bounded acceptance activation."""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
from prepare_acceptance_controller_iam import build_policy


class ControllerIAMPolicyTests(unittest.TestCase):
    def setUp(self):
        self.binding = {
            'activation_id': 'acceptance-1',
            'builder_version_arn': 'arn:aws:lambda:ca-central-1:666730517561:function:tims-factory-builder:8',
            'job_version_id': 'job-version',
            'receipt_plan_digest': 'sha256:' + 'a' * 64,
            'owner_receipt_version_id': 'owner-version',
            'reviewer_receipt_version_id': 'reviewer-version',
        }

    def test_exact_resources_and_actions(self):
        statements = build_policy(self.binding)['Statement']
        self.assertEqual(len(statements), 6)
        self.assertEqual(statements[0]['Condition']['ForAllValues:StringLike']['dynamodb:LeadingKeys'], [
            'FACTORY#tims-software-factory#TASK#deterministic-text-fingerprint',
            'FACTORY#tims-software-factory#TASK#SCOPE#OBJECTIVE#*'])
        self.assertEqual(statements[1]['Condition']['ForAllValues:StringEquals']['dynamodb:LeadingKeys'],
                         ['ACTIVATION#acceptance-1'])
        self.assertTrue(all(s['Condition']['Null']['dynamodb:LeadingKeys'] == 'false'
                            for s in statements[:2]))
        self.assertEqual([s['Condition']['StringEquals']['s3:VersionId'] for s in statements[2:5]],
                         ['job-version', 'owner-version', 'reviewer-version'])
        self.assertEqual(statements[2]['Resource'],
                         'arn:aws:s3:::tims-software-factory-666730517561-ca-central-1/'
                         'factory-autonomy-jobs/acceptance-1/IMPLEMENTATION.json')
        self.assertEqual(statements[5], {'Sid': 'PinnedBuilder', 'Effect': 'Allow',
                         'Action': 'lambda:InvokeFunction', 'Resource': self.binding['builder_version_arn']})
        actions = {action for s in statements for action in
                   (s['Action'] if isinstance(s['Action'], list) else [s['Action']])}
        self.assertFalse(any(a.startswith(('secretsmanager:', 'iam:', 'kms:')) for a in actions))
        self.assertNotIn('s3:PutObject', actions)

    def test_rejects_unreviewed_or_broad_binding(self):
        bad = {'activation_id': '../other', 'builder_version_arn':
               'arn:aws:lambda:ca-central-1:666730517561:function:tims-factory-builder:live',
               'job_version_id': 'null', 'receipt_plan_digest': 'sha256:bad',
               'owner_receipt_version_id': 'owner*', 'reviewer_receipt_version_id': 'reviewer?'}
        for field, value in bad.items():
            with self.subTest(field=field):
                changed = {**self.binding, field: value}
                with self.assertRaises(ValueError):
                    build_policy(changed)
        with self.assertRaises(ValueError):
            build_policy({**self.binding, 'extra_permission': True})


if __name__ == '__main__':
    unittest.main()
