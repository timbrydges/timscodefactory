import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))

from prepare_acceptance_broker_canary import reconcile, validate_changes, validate_plan


TEMPLATE = ROOT / 'infra/acceptance/broker-canary.cloudformation.json'


def changes():
    return [{'ResourceChange': {'LogicalResourceId': name, 'Action': 'Add'}}
            for name in ('BrokerLogs', 'BrokerRole', 'BrokerFunction', 'BrokerVersion')]


class AcceptanceBrokerDeploymentTests(unittest.TestCase):
    def test_template_has_only_probe_resources_and_logs_grant(self):
        template = json.loads(TEMPLATE.read_text())
        resources = template['Resources']
        self.assertEqual(set(resources), {'BrokerLogs', 'BrokerRole', 'BrokerFunction', 'BrokerVersion'})
        function = resources['BrokerFunction']['Properties']
        self.assertEqual(function['Handler'], 'factory_runtime.acceptance_broker_lambda.handler')
        self.assertEqual(function['Environment']['Variables'],
                         {'FACTORY_ACCEPTANCE_BROKER_ENABLED': 'false'})
        self.assertNotIn('ReservedConcurrentExecutions', function)
        self.assertEqual(resources['BrokerVersion']['Properties']['CodeSha256'], {'Ref': 'CodeSha256'})
        policies = resources['BrokerRole']['Properties']['Policies']
        self.assertEqual(len(policies), 1)
        statements = policies[0]['PolicyDocument']['Statement']
        self.assertEqual(len(statements), 1)
        self.assertEqual(set(statements[0]['Action']), {'logs:CreateLogStream', 'logs:PutLogEvents'})

    def test_change_set_and_plan_reject_extra_resources_or_authority(self):
        validate_changes(changes())
        for bad in (changes()[:-1], changes() + [
                {'ResourceChange': {'LogicalResourceId': 'Secrets', 'Action': 'Add'}}],
                [{**changes()[0], 'ResourceChange': {'LogicalResourceId': 'BrokerLogs', 'Action': 'Modify'}}]
                + changes()[1:]):
            with self.subTest(bad=bad), self.assertRaises(RuntimeError):
                validate_changes(bad)
        plan = {'source_commit': 'a' * 40, 'template_sha256': 'digest',
                'status': 'PREPARED_NOT_EXECUTED', 'model_calls_authorized': 0,
                'artifact': {'source_commit': 'a' * 40}, 'changes': changes()}
        validate_plan(plan, commit='a' * 40, template_digest='digest')
        with self.assertRaises(RuntimeError):
            validate_plan({**plan, 'model_calls_authorized': 1},
                          commit='a' * 40, template_digest='digest')

    def test_reconcile_requires_same_executed_change_set_and_completed_stack(self):
        import hashlib
        commit = 'a' * 40
        planned = {'source_commit': commit,
                   'template_sha256': hashlib.sha256(TEMPLATE.read_bytes()).hexdigest(),
                   'status': 'PREPARED_NOT_EXECUTED', 'model_calls_authorized': 0,
                   'artifact': {'source_commit': commit}, 'changes': changes(),
                   'change_set_arn': 'change-set-id'}

        def aws_stub(service, operation, *args):
            if (service, operation) == ('sts', 'get-caller-identity'):
                return {'Account': '666730517561'}
            if operation == 'describe-change-set':
                return {'Changes': changes(), 'ExecutionStatus': 'EXECUTE_COMPLETE',
                        'StackId': 'stack-id'}
            if operation == 'describe-stacks':
                return {'Stacks': [{'StackStatus': 'CREATE_COMPLETE', 'StackId': 'stack-id'}]}
            raise AssertionError((service, operation))

        with tempfile.TemporaryDirectory() as directory, \
                patch('prepare_acceptance_broker_canary.source', return_value=commit), \
                patch('prepare_acceptance_broker_canary.aws', side_effect=aws_stub):
            path = Path(directory) / 'plan.json'
            path.write_text(json.dumps(planned))
            reconcile(path)
            self.assertEqual(json.loads(path.read_text())['status'], 'DEPLOYED_PENDING_PROBE')
            path.write_text(json.dumps(planned))
            with patch('prepare_acceptance_broker_canary.aws', side_effect=lambda service, operation, *args:
                       {**aws_stub(service, operation, *args), 'StackId': 'other-stack'}
                       if operation == 'describe-change-set' else aws_stub(service, operation, *args)):
                with self.assertRaises(RuntimeError):
                    reconcile(path)
            self.assertEqual(json.loads(path.read_text())['status'], 'PREPARED_NOT_EXECUTED')


if __name__ == '__main__':
    unittest.main()
