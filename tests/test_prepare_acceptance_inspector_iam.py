import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))

from prepare_acceptance_inspector_iam import build_policy

MODEL = 'anthropic.claude-sonnet-4-5-20250929-v1:0'
ARN = ('arn:aws:bedrock:ca-central-1:666730517561:'
       'inference-profile/global.' + MODEL)


class InspectorIamTests(unittest.TestCase):
    def description(self):
        return {'inferenceProfileArn': ARN, 'inferenceProfileId': 'global.' + MODEL,
                'status': 'ACTIVE', 'type': 'SYSTEM_DEFINED',
                'models': [{'modelArn': 'arn:aws:bedrock:us-east-1::foundation-model/' + MODEL}]}

    def test_only_exact_profile_and_its_model_can_be_invoked(self):
        statements = build_policy(self.description())['Statement']
        self.assertEqual(len(statements), 2)
        self.assertEqual([item['Action'] for item in statements],
                         ['bedrock:InvokeModel', 'bedrock:InvokeModel'])
        self.assertEqual(statements[0]['Resource'], ARN)
        self.assertEqual(statements[0]['Condition']['StringEquals']['aws:RequestedRegion'],
                         'ca-central-1')
        self.assertEqual(statements[1]['Condition']['StringEquals']['bedrock:InferenceProfileArn'], ARN)
        self.assertEqual(statements[1]['Resource'], [
            'arn:aws:bedrock:ca-central-1::foundation-model/' + MODEL,
            'arn:aws:bedrock:us-east-1::foundation-model/' + MODEL,
            'arn:aws:bedrock:::foundation-model/' + MODEL])
        self.assertNotIn('*', str(statements))

    def test_mismatched_account_model_or_inactive_profile_fails(self):
        description = self.description()
        for change in ({'status': 'INACTIVE'},
                       {'inferenceProfileArn': ARN.replace('666730517561', '111111111111')},
                       {'models': [{'modelArn': 'arn:aws:bedrock:us-east-1::foundation-model/'
                                    'anthropic.claude-other-v1:0'}]},
                       {'models': []}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                build_policy({**description, **change})


if __name__ == '__main__':
    unittest.main()
