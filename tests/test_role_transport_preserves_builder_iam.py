import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import prepare_role_transport_canary as transport


class RoleTransportIamTests(unittest.TestCase):
    def test_existing_stack_requires_both_acceptance_iam_gates(self):
        stack = {'StackStatus': 'UPDATE_COMPLETE', 'Parameters': [
            {'ParameterKey': 'EnableBuilderAcceptanceIam', 'ParameterValue': 'true'},
            {'ParameterKey': 'EnableInspectorAcceptanceIam', 'ParameterValue': 'true'}]}
        transport.validate_existing_stack(stack)
        for key in ('EnableBuilderAcceptanceIam', 'EnableInspectorAcceptanceIam'):
            changed = {'StackStatus': 'UPDATE_COMPLETE', 'Parameters': [
                {'ParameterKey': 'EnableBuilderAcceptanceIam', 'ParameterValue': 'true'},
                {'ParameterKey': 'EnableInspectorAcceptanceIam', 'ParameterValue': 'true'}]}
            next(p for p in changed['Parameters'] if p['ParameterKey'] == key)['ParameterValue'] = 'false'
            with self.assertRaisesRegex(RuntimeError, 'must remain enabled'):
                transport.validate_existing_stack(changed)

    def test_change_set_must_preserve_both_parameters(self):
        previous = [
            {'ParameterKey': 'EnableBuilderAcceptanceIam', 'UsePreviousValue': True},
            {'ParameterKey': 'EnableInspectorAcceptanceIam', 'UsePreviousValue': True}]
        transport.validate_builder_parameter(previous)
        explicit = [
            {'ParameterKey': 'EnableBuilderAcceptanceIam', 'ParameterValue': 'true'},
            {'ParameterKey': 'EnableInspectorAcceptanceIam', 'ParameterValue': 'true'}]
        transport.validate_builder_parameter(explicit)
        for values in (
            [],
            [{'ParameterKey': 'EnableBuilderAcceptanceIam', 'UsePreviousValue': True}],
            [{'ParameterKey': 'EnableBuilderAcceptanceIam', 'UsePreviousValue': True},
             {'ParameterKey': 'EnableInspectorAcceptanceIam', 'ParameterValue': 'false'}],
        ):
            with self.assertRaisesRegex(RuntimeError, 'must preserve'):
                transport.validate_builder_parameter(values)


if __name__ == '__main__':
    unittest.main()
