import sys
import json
import unittest
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import prepare_role_transport_canary as transport


class RoleTransportIamTests(unittest.TestCase):
    def test_expired_price_stops_before_any_aws_operation(self):
        policy = json.loads((ROOT /
            'factory/evidence/acceptance-inspector-sonnet45-budget-policy-2026-09-30.json'
            ).read_text())
        expiry = datetime.fromisoformat(policy['expires_at'].replace('Z', '+00:00'))
        with patch.object(transport, 'datetime') as clock:
            clock.now.return_value = expiry - timedelta(seconds=1)
            transport.validate_inspector_price()
            clock.now.return_value = expiry
            with patch.object(transport, 'aws') as aws:
                for operation, args in ((transport.prepare, ('unused.zip', 'unused.json')),
                                        (transport.execute, ('unused.json',))):
                    with self.assertRaisesRegex(RuntimeError, 'stale or unsafe'):
                        operation(*args)
                aws.assert_not_called()

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
