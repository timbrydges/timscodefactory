import copy
import unittest
from prepare_handoff002_foundation import render as foundation, STACK
from prepare_handoff002_access import render, policy, validate_changes
from factory_state.model import StateError


class HandoffAccessTests(unittest.TestCase):
    def setUp(self):
        self.args = {'source_commit': 'a'*40, 'code': {'S3Bucket': 'bucket', 'S3Key': 'code.zip', 'S3ObjectVersion': 'v1'}}
        self.current = foundation(**self.args)
        self.template = render(self.current, **self.args)
        self.change = {'Status': 'CREATE_COMPLETE', 'ExecutionStatus': 'AVAILABLE',
            'StackId': 'arn:aws:cloudformation:ca-central-1:666730517561:stack/'+STACK+'/fixture',
            'Changes': [{'Type': 'Resource', 'ResourceChange': {'LogicalResourceId': role+'Access',
                'Action': 'Add', 'ResourceType': 'AWS::IAM::Policy'}} for role in ('Builder', 'Inspector', 'Qa')]}

    def test_only_three_policies_added_without_function_activation(self):
        self.assertEqual({k:v for k,v in self.template['Resources'].items() if k in self.current['Resources']}, self.current['Resources'])
        self.assertEqual(validate_changes(self.template, self.change, current=self.current, **self.args)['new_policies'], 3)

    def test_own_row_and_lambda_context_cannot_reuse_old_attempts(self):
        for role in ('builder', 'inspector', 'qa'):
            statements = policy(role)['Statement']
            row = statements[0]
            self.assertEqual(row['Action'], ['dynamodb:PutItem', 'dynamodb:UpdateItem'])
            self.assertTrue(row['Resource'].endswith(':table/tims-factory-handoff-002-attempts'))
            self.assertEqual(row['Condition']['ForAllValues:StringEquals']['dynamodb:LeadingKeys'],
                ['HANDOFF#002#TASK#authenticated-handoff-002#ROLE#'+role])
            for statement in statements:
                if statement['Action'] == 'kms:Decrypt':
                    self.assertEqual(statement['Condition']['StringEquals']['kms:EncryptionContext:SecretVersionId'],
                        'ebb6cc21-2df9-4b06-8f55-2b0661f27f69')
                else:
                    self.assertTrue(statement['Condition']['ArnEquals']['lambda:SourceFunctionArn'].endswith(':function:tims-factory-handoff-002-'+role))

    def test_existing_resource_changes_pagination_and_permission_tampering_rejected(self):
        for action in ('Modify', 'Remove'):
            changed = copy.deepcopy(self.change); changed['Changes'][0]['ResourceChange']['Action'] = action
            with self.assertRaises(StateError): validate_changes(self.template, changed, current=self.current, **self.args)
        changed = copy.deepcopy(self.template)
        changed['Resources']['BuilderAccess']['Properties']['PolicyDocument']['Statement'][0]['Resource'] = '*'
        with self.assertRaises(StateError): validate_changes(changed, self.change, current=self.current, **self.args)
        with self.assertRaises(StateError): validate_changes(self.template, {**self.change, 'NextToken': 'more'}, current=self.current, **self.args)
        changed = copy.deepcopy(self.current)
        changed['Resources']['BuilderFunction']['Properties']['ReservedConcurrentExecutions'] = 1
        with self.assertRaises(StateError): render(changed, **self.args)
