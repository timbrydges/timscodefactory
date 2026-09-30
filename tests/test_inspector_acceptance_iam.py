import json
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))

import prepare_inspector_acceptance_iam as inspector_iam


class InspectorAcceptanceIamTests(unittest.TestCase):
    def test_template_is_exact_and_operational_switch_stays_off(self):
        digest = inspector_iam.validate_template()
        self.assertEqual(len(digest), 64)
        template = json.loads(inspector_iam.TEMPLATE.read_text())
        policy = template['Resources']['InspectorRole']['Properties']['Policies'][1]['Fn::If']
        self.assertEqual(policy[0], 'InspectorAcceptanceIamEnabled')
        self.assertEqual(policy[1]['PolicyName'], 'acceptance-inspector-fallback-sonnet-4-5')
        self.assertEqual(policy[2], {'Ref': 'AWS::NoValue'})
        self.assertEqual(
            template['Resources']['InspectorFunction']['Properties']['Environment']['Variables']
            ['FACTORY_OPERATIONAL_EXECUTION_ENABLED'], 'false')

    def test_only_role_and_dynamic_lambda_role_reference_may_change(self):
        changes = [
            {'ResourceChange': {'LogicalResourceId': 'InspectorRole',
                'ResourceType': 'AWS::IAM::Role', 'Action': 'Modify', 'Replacement': 'False'}},
            {'ResourceChange': {'LogicalResourceId': 'InspectorFunction',
                'ResourceType': 'AWS::Lambda::Function', 'Action': 'Modify',
                'Replacement': 'False', 'Scope': ['Properties'],
                'Details': [{'Target': {'Attribute': 'Properties', 'Name': 'Role',
                                        'RequiresRecreation': 'Never'},
                             'Evaluation': 'Dynamic',
                             'ChangeSource': 'ResourceAttribute',
                             'CausingEntity': 'InspectorRole.Arn'}]}}
        ]
        inspector_iam.validate_changes(changes)
        with self.assertRaisesRegex(RuntimeError, 'only InspectorRole'):
            inspector_iam.validate_changes(changes + [
                {'ResourceChange': {'LogicalResourceId': 'BuilderRole'}}])

    def test_execution_requires_separate_explicit_mode(self):
        self.assertIn('prepare', {'prepare', 'execute', 'reconcile', 'verify'})
        self.assertIn('execute', {'prepare', 'execute', 'reconcile', 'verify'})
        self.assertNotEqual(inspector_iam.PARAMETER, 'EnableBuilderAcceptanceIam')


if __name__ == '__main__':
    unittest.main()
