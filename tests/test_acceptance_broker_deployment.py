import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))

from prepare_acceptance_broker_canary import validate_changes, validate_plan


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
        self.assertEqual(function['ReservedConcurrentExecutions'], 1)
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


if __name__ == '__main__':
    unittest.main()
