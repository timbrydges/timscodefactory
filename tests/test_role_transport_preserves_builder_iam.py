import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import prepare_role_transport_canary as transport


class RoleTransportIamTests(unittest.TestCase):
    def test_existing_stack_requires_enabled_builder_iam(self):
        stack = {'StackStatus': 'UPDATE_COMPLETE', 'Parameters': [
            {'ParameterKey': 'EnableBuilderAcceptanceIam', 'ParameterValue': 'true'}]}
        transport.validate_existing_stack(stack)
        stack['Parameters'][0]['ParameterValue'] = 'false'
        with self.assertRaisesRegex(RuntimeError, 'must remain enabled'):
            transport.validate_existing_stack(stack)

    def test_change_set_must_preserve_parameter(self):
        transport.validate_builder_parameter([{'ParameterKey': 'EnableBuilderAcceptanceIam',
                                              'UsePreviousValue': True}])
        transport.validate_builder_parameter([{'ParameterKey': 'EnableBuilderAcceptanceIam',
                                              'ParameterValue': 'true'}])
        for values in ([], [{'ParameterKey': 'EnableBuilderAcceptanceIam',
                             'ParameterValue': 'false'}]):
            with self.assertRaisesRegex(RuntimeError, 'must preserve'):
                transport.validate_builder_parameter(values)


if __name__ == '__main__':
    unittest.main()
