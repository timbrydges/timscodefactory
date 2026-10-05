import copy
import json
import sys
import unittest
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / 'src'), str(ROOT / 'scripts')]
import prepare_pilot002_qa_shutdown as qa
import prepare_inspector_recovery001_shutdown as recovery
from factory_state.model import StateError


class QaShutdownTests(unittest.TestCase):
    def setUp(self):
        self.now = datetime(2026, 10, 5, tzinfo=timezone.utc)
        self.deadline = int(self.now.timestamp()) + 1200
        self.template = qa.render(self.deadline, now=self.now)
        self.changes = {'Status': 'CREATE_COMPLETE', 'ExecutionStatus': 'AVAILABLE',
            'StackId': 'arn:aws:cloudformation:ca-central-1:666730517561:stack/' + qa.STACK + '/fixture',
            'Changes': [{'Type': 'Resource', 'ResourceChange': {'LogicalResourceId': name,
                'ResourceType': value['Type'], 'Action': 'Add'}}
                for name, value in self.template['Resources'].items()]}

    def test_qa_only_and_recovery_unchanged(self):
        self.assertNotIn('inspector', json.dumps(self.template))
        resources = self.template['Resources']
        role = resources['ShutdownRole']['Properties']
        self.assertEqual(role['Policies'][0]['PolicyDocument']['Statement'],
            [{'Effect': 'Allow', 'Action': 'lambda:PutFunctionConcurrency', 'Resource': qa.FUNCTION_ARN}])
        self.assertEqual(role['AssumeRolePolicyDocument']['Statement'][0]['Condition']['StringEquals'],
            {'aws:SourceAccount': '666730517561', 'aws:SourceArn': qa.GROUP_ARN})
        schedule = resources['ShutdownSchedule']['Properties']
        self.assertEqual(schedule['State'], 'DISABLED')
        self.assertEqual(json.loads(schedule['Target']['Input']),
            {'FunctionName': qa.FUNCTION_ARN, 'ReservedConcurrentExecutions': 0})
        self.assertEqual(schedule['Target']['RoleArn'], qa.ROLE_ARN)
        original = recovery.properties(self.deadline, now=self.now)
        self.assertEqual(json.loads(original['Target']['Input'])['FunctionName'], recovery.FUNCTION_ARN)

    def test_exact_preview_rejects_arming_cross_role_and_permission_expansion(self):
        self.assertFalse(qa.validate_preview(self.template, self.changes, self.deadline, now=self.now)['armed'])
        for mutate in (
            lambda t: t['Resources']['ShutdownSchedule']['Properties'].update(State='ENABLED'),
            lambda t: t['Resources']['ShutdownRole']['Properties']['Policies'][0]['PolicyDocument']['Statement'][0].update(Action='lambda:*'),
            lambda t: t['Resources']['ShutdownRole']['Properties']['Policies'][0]['PolicyDocument']['Statement'][0].update(Resource=recovery.FUNCTION_ARN),
        ):
            bad = copy.deepcopy(self.template)
            mutate(bad)
            with self.assertRaises(StateError):
                qa.validate_preview(bad, self.changes, self.deadline, now=self.now)
        for changes in ({**self.changes, 'NextToken': 'more'},
                        {**self.changes, 'Changes': [self.changes['Changes'][0]] * 3}):
            with self.assertRaises(StateError):
                qa.validate_preview(self.template, changes, self.deadline, now=self.now)

    def test_arm_requires_exact_qa_target_and_short_aware_window(self):
        good = qa.properties(self.deadline, now=self.now, armed=True)
        good['StartDate'] = datetime.fromisoformat(good['StartDate'])
        self.assertEqual(qa.validate_armed(good, self.deadline, now=self.now)['deadline'], self.deadline)
        for bad in (recovery.properties(self.deadline, now=self.now, armed=True),
                    qa.properties(self.deadline, now=self.now),
                    {**good, 'Target': {**good['Target'], 'Input': '{"ReservedConcurrentExecutions":1}'}}):
            with self.assertRaises(StateError):
                qa.validate_armed(bad, self.deadline, now=self.now)
        for deadline in (True, self.deadline - 601, self.deadline + 601):
            with self.assertRaises(StateError):
                qa.render(deadline, now=self.now)
        with self.assertRaises(StateError):
            qa.render(self.deadline, now=self.now.replace(tzinfo=None))


if __name__ == '__main__':
    unittest.main()
