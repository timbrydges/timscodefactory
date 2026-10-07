from types import SimpleNamespace
from pathlib import Path
import unittest
from unittest.mock import Mock, patch

from factory_runtime import security_role_lambda as entry
from factory_state.model import StateError
from test_security_provider_scope import NOW


class SecurityEntryTests(unittest.TestCase):
    def setUp(self):
        self.env={'FACTORY_SECURITY_ENABLED':'true','AWS_REGION':'ca-central-1',
            'AWS_LAMBDA_FUNCTION_NAME':entry.NAME}
        self.context=SimpleNamespace(invoked_function_arn=
            'arn:aws:lambda:ca-central-1:666730517561:function:'+entry.NAME+':1',
            get_remaining_time_in_millis=lambda:180000)

    def run_entry(self):
        return entry.dispatch({},self.context,root=Path('unused'),env=self.env,clock=lambda:NOW)

    def test_disabled_stops_before_files_or_clients(self):
        self.env.pop('FACTORY_SECURITY_ENABLED')
        with patch.object(entry,'load_deployment') as files,patch.object(entry,'_aws_session') as aws:
            with self.assertRaisesRegex(StateError,'disabled'):self.run_entry()
            files.assert_not_called();aws.assert_not_called()

    def test_alias_wrong_region_and_short_deadline_stop_before_files(self):
        for change in ('alias','region','deadline'):
            self.setUp()
            if change=='alias':self.context.invoked_function_arn=self.context.invoked_function_arn[:-1]+'live'
            if change=='region':self.env['AWS_REGION']='us-east-1'
            if change=='deadline':self.context.get_remaining_time_in_millis=lambda:1000
            with patch.object(entry,'load_deployment') as files:
                with self.subTest(change=change),self.assertRaises(StateError):self.run_entry()
                files.assert_not_called()

    def test_wrong_event_stops_before_aws_or_allowance(self):
        deployment=Mock()
        with patch.object(entry,'load_deployment',return_value=deployment), \
                patch.object(entry,'_aws_session') as aws,patch.object(entry,'load_allowance') as allowance:
            with self.assertRaises(StateError):self.run_entry()
            aws.assert_not_called();allowance.assert_not_called()

    def test_deployment_failure_is_redacted_and_never_creates_clients(self):
        with patch.object(entry,'load_deployment',side_effect=ValueError('sensitive fixture')), \
                patch.object(entry,'_aws_session') as aws:
            with self.assertRaises(StateError) as caught:self.run_entry()
            self.assertNotIn('sensitive',str(caught.exception));aws.assert_not_called()


if __name__ == '__main__':unittest.main()
