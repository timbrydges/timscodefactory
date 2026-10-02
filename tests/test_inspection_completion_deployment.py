import copy
import unittest

from prepare_inspection_completion import templates, validate_changes


class CompletionDeploymentTests(unittest.TestCase):
    def changes(self):
        return [{'ResourceChange': {'LogicalResourceId': name, 'Action': 'Modify',
            'ResourceType': kind, 'Replacement': replacement, 'Scope': ['Properties'],
            'Details': [{'Target': {'Attribute': 'Properties', 'Name': prop}}]}}
            for name, kind, replacement, prop in [
                ('ControllerRole', 'AWS::IAM::Role', 'False', 'Policies'),
                ('ControllerFunction', 'AWS::Lambda::Function', 'False', 'Environment'),
                ('ControllerVersion', 'AWS::Lambda::Version', 'True', 'Description'),
                ('AcceptanceAlias', 'AWS::Lambda::Alias', 'False', 'FunctionVersion')]]

    def test_temporary_access_has_exact_partition_expiry_and_no_provider_or_secret_access(self):
        baseline, proposed = templates()
        self.assertEqual(len(baseline['Resources']), 5)
        resources = proposed['Resources']
        self.assertEqual(resources['ControllerFunction']['Properties']['Environment']['Variables'], {
            'FACTORY_AUTONOMY_CONTROLLER_ENABLED': 'false', 'FACTORY_INSPECTION_COMPLETION_ENABLED': 'true'})
        policy = resources['ControllerRole']['Properties']['Policies'][-1]['PolicyDocument']
        statement, = policy['Statement']
        self.assertEqual(statement['Action'], ['dynamodb:GetItem', 'dynamodb:PutItem', 'dynamodb:UpdateItem'])
        self.assertEqual(statement['Condition']['ForAllValues:StringEquals']['dynamodb:LeadingKeys'],
            ['FACTORY#tims-software-factory#TASK#deterministic-text-fingerprint'])
        self.assertEqual(statement['Condition']['DateLessThan']['aws:CurrentTime'], '2026-10-03T03:01:53+00:00')
        self.assertEqual(len(baseline['Resources']['ControllerRole']['Properties']['Policies']), 1)
        self.assertNotIn('Description', baseline['Resources']['ControllerVersion']['Properties'])

    def test_change_set_rejects_added_resources_replacements_or_unrelated_changes(self):
        validate_changes(self.changes())
        for field, value in [('Action', 'Remove'), ('Replacement', 'True'), ('ResourceType', 'AWS::IAM::User')]:
            changed = self.changes()
            changed[0]['ResourceChange'][field] = value
            with self.assertRaises(RuntimeError): validate_changes(changed)
        changed = self.changes()
        changed[0]['ResourceChange']['Details'][0]['Target']['Name'] = 'AssumeRolePolicyDocument'
        with self.assertRaises(RuntimeError): validate_changes(changed)
        with self.assertRaises(RuntimeError): validate_changes(self.changes() + [copy.deepcopy(changed[0])])


if __name__ == '__main__': unittest.main()
