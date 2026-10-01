import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))
sys.path.insert(0, str(ROOT / 'scripts'))

from factory_runtime.autonomy_controller_lambda import handler
from factory_state.model import StateError
from prepare_disabled_autonomy_controller import validate_changes, validate_template


class DisabledAutonomyControllerTests(unittest.TestCase):
    def test_probe_only_and_disabled(self):
        with tempfile.TemporaryDirectory() as directory:
            Path(directory, 'BUILD.json').write_text(json.dumps({'source_commit': 'a' * 40}))
            event = {'kind': 'disabled_controller_probe', 'source_commit': 'a' * 40,
                     'nonce': 'b' * 32, 'task_id': 'deterministic-text-fingerprint'}
            with patch.dict('os.environ', {'LAMBDA_TASK_ROOT': directory,
                                           'FACTORY_AUTONOMY_CONTROLLER_ENABLED': 'false'}):
                self.assertEqual(handler(event, None), {
                    'kind': 'disabled_controller_probe_result',
                    'source_commit': 'a' * 40, 'nonce': 'b' * 32,
                    'task_id': 'deterministic-text-fingerprint',
                    'controller_enabled': False, 'schedule_enabled': False,
                    'model_calls': 0, 'release_dispatched': False})
                for bad in ({'factory_id': 'factory', 'task_id': event['task_id'],
                             'mode': 'acceptance'}, {**event, 'task_id': 'other'},
                            {**event, 'extra': True}):
                    with self.subTest(event=bad), self.assertRaises(StateError):
                        handler(bad, None)
            with patch.dict('os.environ', {'LAMBDA_TASK_ROOT': directory,
                                           'FACTORY_AUTONOMY_CONTROLLER_ENABLED': 'true'}):
                with self.assertRaises(StateError):
                    handler(event, None)

    def test_template_and_change_set_allow_only_disabled_shell(self):
        self.assertEqual(len(validate_template()), 64)
        template = json.loads((ROOT / 'infra/acceptance/controller-disabled.cloudformation.json').read_text())
        self.assertEqual(template['Resources']['AcceptanceAlias']['Properties']['Name'], 'acceptance')
        self.assertGreater(template['Resources']['ControllerFunction']['Properties']['Timeout'], 185)
        names = list(template['Resources'])
        changes = [{'ResourceChange': {'LogicalResourceId': name, 'Action': 'Add'}}
                   for name in names]
        validate_changes(changes)
        with self.assertRaises(RuntimeError):
            validate_changes(changes + [{'ResourceChange': {'LogicalResourceId': 'Extra',
                                                            'Action': 'Add'}}])

    def test_update_rejects_iam_changes_deletions_and_function_replacement(self):
        changes = [{'ResourceChange': {'LogicalResourceId': name, 'Action': 'Modify',
                                       'Replacement': replacement}}
                   for name, replacement in [('ControllerFunction', 'False'),
                        ('ControllerVersion', 'True'), ('AcceptanceAlias', 'False')]]
        validate_changes(changes, 'UPDATE')
        for field, value in [('LogicalResourceId', 'ControllerRole'),
                             ('Action', 'Remove'), ('Replacement', 'True')]:
            bad = json.loads(json.dumps(changes))
            bad[0]['ResourceChange'][field] = value
            with self.subTest(field=field), self.assertRaises(RuntimeError):
                validate_changes(bad, 'UPDATE')


if __name__ == '__main__':
    unittest.main()
