import copy
import unittest
from prepare_handoff002_foundation import render, validate_changes, STACK
from factory_state.model import StateError


class HandoffFoundationTests(unittest.TestCase):
    def setUp(self):
        self.args = {'source_commit': 'a'*40, 'code': {'S3Bucket': 'reviewed-bucket', 'S3Key': 'handoff/code.zip', 'S3ObjectVersion': 'version-1'}}
        self.template = render(**self.args)
        self.changes = {'Status': 'CREATE_COMPLETE', 'ExecutionStatus': 'AVAILABLE',
            'StackId': 'arn:aws:cloudformation:ca-central-1:666730517561:stack/'+STACK+'/fixture',
            'Changes': [{'Type': 'Resource', 'ResourceChange': {'LogicalResourceId': name,
                'Action': 'Add', 'ResourceType': resource['Type']}} for name, resource in self.template['Resources'].items()]}

    def test_disabled_functions_retained_ledger_and_no_permissions(self):
        resources = self.template['Resources']
        self.assertEqual(len(resources), 7)
        self.assertTrue(resources['Attempts']['Properties']['DeletionProtectionEnabled'])
        self.assertEqual(resources['Attempts']['DeletionPolicy'], 'Retain')
        self.assertNotIn('TimeToLiveSpecification', resources['Attempts']['Properties'])
        for role in ('Builder', 'Inspector', 'Qa'):
            function = resources[role+'Function']['Properties']
            self.assertEqual(function['ReservedConcurrentExecutions'], 0)
            self.assertEqual(function['Environment']['Variables']['FACTORY_HANDOFF002_ENABLED'], 'false')
            self.assertEqual(function['Code'], self.args['code'])
        self.assertFalse(any(r['Type'].startswith('AWS::IAM') for r in resources.values()))
        self.assertEqual(validate_changes(self.template, self.changes, **self.args)['iam_changes'], 0)

    def test_enabled_function_or_existing_resource_change_rejected(self):
        altered = copy.deepcopy(self.template)
        altered['Resources']['BuilderFunction']['Properties']['ReservedConcurrentExecutions'] = 1
        with self.assertRaises(StateError): validate_changes(altered, self.changes, **self.args)
        for action in ('Modify', 'Remove'):
            altered = copy.deepcopy(self.changes)
            altered['Changes'][0]['ResourceChange']['Action'] = action
            with self.assertRaises(StateError): validate_changes(self.template, altered, **self.args)
        altered = copy.deepcopy(self.changes); altered['NextToken'] = 'more'
        with self.assertRaises(StateError): validate_changes(self.template, altered, **self.args)

    def test_mutable_package_reference_rejected(self):
        with self.assertRaises(StateError): render(**{**self.args, 'code': {**self.args['code'], 'S3ObjectVersion': 'null'}})
