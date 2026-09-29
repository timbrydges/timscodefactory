import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))

from prepare_acceptance_broker_update import TEMPLATE, execute, validate_changes
from prepare_acceptance_broker_update import validate_disabled_template, validate_role_iam

COMMIT = 'a' * 40
OLD_ARN = 'arn:aws:lambda:ca-central-1:666730517561:function:tims-factory-provider-broker:1'


def changes():
    return [{'ResourceChange': {'LogicalResourceId': 'BrokerFunction',
                                'Action': 'Modify', 'Replacement': 'False'}},
            {'ResourceChange': {'LogicalResourceId': 'BrokerVersion',
                                'Action': 'Modify', 'Replacement': 'True'}}]


class AcceptanceBrokerUpdateTests(unittest.TestCase):
    def test_code_updater_preserves_staged_broker_iam_and_disabled_switch(self):
        validate_disabled_template()
        template = json.loads(TEMPLATE.read_text())
        self.assertEqual(len(template['Resources']['BrokerRole']['Properties']['ManagedPolicyArns']), 2)
        self.assertEqual(template['Resources']['BrokerFunction']['Properties'][
            'Environment']['Variables']['FACTORY_ACCEPTANCE_BROKER_ENABLED'], 'false')

    def test_role_iam_rejects_extra_policy_before_deployment(self):
        def aws_stub(service, operation, *args):
            if operation == 'list-attached-role-policies':
                return {'AttachedPolicies': [{'PolicyName': 'unexpected',
                                              'PolicyArn': 'arn:aws:iam::666730517561:policy/unexpected'}]}
            if operation == 'list-role-policies':
                return {'PolicyNames': ['canary-logs-only']}
            raise AssertionError('unexpected cloud action')
        with patch('prepare_acceptance_broker_update.aws', side_effect=aws_stub):
            with self.assertRaisesRegex(RuntimeError, 'exact staged IAM'):
                validate_role_iam()

    def test_only_function_and_immutable_version_may_change(self):
        validate_changes(changes())
        for bad in (
                changes()[:-1],
                changes() + [{'ResourceChange': {'LogicalResourceId': 'BrokerRole',
                                                'Action': 'Modify', 'Replacement': 'False'}}],
                [changes()[0], {'ResourceChange': {'LogicalResourceId': 'BrokerVersion',
                                                  'Action': 'Modify', 'Replacement': 'False'}}],
                [{'ResourceChange': {'LogicalResourceId': 'BrokerFunction',
                                     'Action': 'Replace', 'Replacement': 'True'}}, changes()[1]]):
            with self.subTest(bad=bad), self.assertRaises(RuntimeError):
                validate_changes(bad)

    def test_execute_rejects_changed_stack_before_cloud_mutation(self):
        plan = {'source_commit': COMMIT,
                'template_sha256': hashlib.sha256(TEMPLATE.read_bytes()).hexdigest(),
                'status': 'PREPARED_NOT_EXECUTED', 'model_calls_authorized': 0,
                'artifact': {'source_commit': COMMIT}, 'changes': changes(),
                'previous_version': OLD_ARN, 'stack_id': 'stack-id',
                'change_set_arn': 'change-set-id'}
        calls = []

        def aws_stub(service, operation, *args):
            calls.append(operation)
            if operation == 'get-caller-identity':
                return {'Account': '666730517561'}
            if operation == 'describe-stacks':
                return {'Stacks': [{'StackStatus': 'UPDATE_COMPLETE', 'StackId': 'stack-id',
                                    'Outputs': [{'OutputKey': 'BrokerVersionArn',
                                                 'OutputValue': OLD_ARN.replace(':1', ':2')}]}]}
            raise AssertionError('unexpected cloud action: ' + operation)

        with tempfile.TemporaryDirectory() as directory, \
                patch('prepare_acceptance_broker_update.source', return_value=COMMIT), \
                patch('prepare_acceptance_broker_update.validate_disabled_template'), \
                patch('prepare_acceptance_broker_update.aws', side_effect=aws_stub):
            path = Path(directory) / 'plan.json'
            path.write_text(json.dumps(plan))
            with self.assertRaisesRegex(RuntimeError, 'version changed'):
                execute(path)
        self.assertNotIn('execute-change-set', calls)


if __name__ == '__main__':
    unittest.main()
