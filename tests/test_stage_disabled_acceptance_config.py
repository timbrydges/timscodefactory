import copy
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / 'scripts'), str(ROOT / 'src')]

import stage_disabled_acceptance_config as stage
from prepare_disabled_autonomy_schedule import assert_controller


def changes(component='controller'):
    return [{'ResourceChange': {'LogicalResourceId': stage.COMPONENTS[component][2],
        'ResourceType': 'AWS::Lambda::Function', 'Action': 'Modify',
        'Replacement': 'False', 'Scope': ['Properties'], 'Details': [{
            'Target': {'Attribute': 'Properties', 'Name': 'Environment', 'RequiresRecreation': 'Never'},
            'Evaluation': 'Static', 'ChangeSource': 'DirectModification'}]}}]


class DisabledConfigTests(unittest.TestCase):
    def test_canary_has_no_activation_settings_and_cleanup_uses_exact_original(self):
        bundle = stage.canary_bundle('controller', 'a' * 32)
        self.assertEqual(bundle['environment_updates']['controller'], {
            'FACTORY_AUTONOMY_CONTROLLER_ENABLED': 'false',
            'FACTORY_CONFIGURATION_CANARY': 'a' * 32})
        plan = {'mode': 'canary', 'component': 'controller', 'bundle': bundle, 'canary_nonce': 'a' * 32}
        with patch.object(stage, 'verify') as verify, \
             patch.object(stage, 'checked', return_value=(plan, {}, {})), \
             patch.object(stage, 'prepare_bundle') as prepare:
            stage.prepare_cleanup('canary.json', 'cleanup.json')
            verify.assert_called_once_with('canary.json')
            self.assertEqual(prepare.call_args.args, ('controller', bundle, 'cleanup.json'))
            self.assertEqual(prepare.call_args.kwargs['mode'], 'canary_cleanup')
        for nonce in ('', 'x' * 32, True):
            with self.subTest(nonce=nonce), self.assertRaises(RuntimeError):
                stage.canary_bundle('controller', nonce)

    def test_render_preserves_everything_except_disabled_environment_updates(self):
        for component, (_, _, logical, _, flag) in stage.COMPONENTS.items():
            bundle = {'status': 'PREPARED_DISABLED_NOT_DEPLOYED',
                'activation_authorized': False, 'model_calls_authorized': 0,
                'environment_updates': {component: {flag: 'false', 'CONFIG': '{}'}}}
            baseline, proposed = stage.render(component, bundle)
            modified = copy.deepcopy(proposed)
            modified['Resources'][logical]['Properties']['Environment'] = baseline['Resources'][logical]['Properties']['Environment']
            self.assertEqual(modified, baseline)
            bundle['environment_updates'][component][flag] = 'true'
            with self.assertRaisesRegex(RuntimeError, 'disabled'):
                stage.render(component, bundle)

    def test_change_set_rejects_code_iam_alias_versions_and_replacements(self):
        for component in stage.COMPONENTS:
            stage.validate_changes(component, changes(component))
        for field, value in [('Action', 'Remove'), ('Replacement', 'True'),
            ('LogicalResourceId', 'ControllerRole'), ('ResourceType', 'AWS::IAM::Role')]:
            changed = changes()
            changed[0]['ResourceChange'][field] = value
            with self.subTest(field=field), self.assertRaises(RuntimeError):
                stage.validate_changes('controller', changed)
        for extra in ('ControllerVersion', 'AcceptanceAlias', 'ControllerRole'):
            changed = changes() + changes()
            changed[1]['ResourceChange']['LogicalResourceId'] = extra
            with self.subTest(extra=extra), self.assertRaises(RuntimeError):
                stage.validate_changes('controller', changed)
        changed = changes()
        changed[0]['ResourceChange']['Details'][0]['Target']['Name'] = 'Code'
        with self.assertRaises(RuntimeError):
            stage.validate_changes('controller', changed)

    def test_drift_stops_execution_before_any_mutation(self):
        plan = {'status': 'PREPARED_NOT_EXECUTED', 'component': 'controller', 'before': {'revision_id': 'old'}}
        with patch.object(stage, 'checked', return_value=(plan, {}, {})), \
             patch.object(stage, 'snapshot', return_value={'revision_id': 'new'}), \
             patch.object(stage, 'aws') as api:
            with self.assertRaisesRegex(RuntimeError, 'changed since'):
                stage.execute('unused')
            api.assert_not_called()

    def test_uncertain_execute_persists_attempt_and_cannot_be_retried(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'plan.json'
            plan = {'status': 'PREPARED_NOT_EXECUTED', 'component': 'controller',
                    'before': {}, 'change_set_arn': 'reviewed-change'}
            with patch.object(stage, 'checked', return_value=(plan, {}, {})), \
                 patch.object(stage, 'snapshot', return_value={}), \
                 patch.object(stage, 'check_change'), \
                 patch.object(stage, 'aws', side_effect=TimeoutError) as api:
                with self.assertRaises(TimeoutError):
                    stage.execute(path)
                self.assertEqual(json.loads(path.read_text())['status'], 'EXECUTION_ATTEMPTED_RECONCILE_REQUIRED')
                with self.assertRaisesRegex(RuntimeError, 'single-attempt'):
                    stage.execute(path)
                api.assert_called_once_with('cloudformation', 'execute-change-set', '--change-set-name', 'reviewed-change')

    def test_reconciliation_rejects_alias_or_published_version_change(self):
        plan = {'status': 'EXECUTION_ATTEMPTED_RECONCILE_REQUIRED', 'component': 'controller',
                'before': {'alias': {'FunctionVersion': '3'}, 'outputs': [], 'revision_id': 'before'}}
        with patch.object(stage, 'checked', return_value=(plan, {}, {})), \
             patch.object(stage, 'check_change'), \
             patch.object(stage, 'snapshot', return_value={
                 'alias': {'FunctionVersion': '4'}, 'outputs': [], 'revision_id': 'after'}), \
             patch.object(stage, 'save') as save:
            with self.assertRaisesRegex(RuntimeError, 'published versions or alias'):
                stage.verify('unused')
            save.assert_not_called()

    def test_schedule_controller_check_accepts_completed_updates_only(self):
        version = stage.TARGET.removesuffix(':acceptance') + ':3'
        stack = {'StackStatus': 'UPDATE_COMPLETE', 'Outputs': [
            {'OutputKey': 'AcceptanceAliasArn', 'OutputValue': stage.TARGET},
            {'OutputKey': 'ControllerVersionArn', 'OutputValue': version}]}
        alias = {'AliasArn': stage.TARGET, 'FunctionVersion': '3'}
        config = {'Environment': {'Variables': {'FACTORY_AUTONOMY_CONTROLLER_ENABLED': 'false'}},
                  'Role': 'arn:aws:iam::666730517561:role/tims-software-factory-autonomy-controller-disabled'}
        with patch('prepare_disabled_autonomy_schedule.aws', side_effect=[{'Stacks': [stack]}, alias, config]):
            assert_controller()
        for status in ('UPDATE_IN_PROGRESS', 'UPDATE_ROLLBACK_COMPLETE'):
            with patch('prepare_disabled_autonomy_schedule.aws', return_value={'Stacks': [{**stack, 'StackStatus': status}]}):
                with self.assertRaisesRegex(RuntimeError, 'completed deployment'):
                    assert_controller()


if __name__ == '__main__':
    unittest.main()
