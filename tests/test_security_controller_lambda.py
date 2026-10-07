from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from factory_runtime import security_controller_lambda as entry
from factory_state.model import StateError
from test_security_provider_scope import NOW


class ControllerBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.env={'FACTORY_SECURITY_CONTROLLER_ENABLED':'true','AWS_REGION':'ca-central-1',
            'AWS_LAMBDA_FUNCTION_NAME':entry.NAME}
        self.context=SimpleNamespace(invoked_function_arn=
            'arn:aws:lambda:ca-central-1:666730517561:function:'+entry.NAME+':1',
            get_remaining_time_in_millis=lambda:300000)

    def run_entry(self,event=None):
        return entry.dispatch(entry.EVENT if event is None else event,self.context,
            root=Path('unused'),env=self.env,clock=lambda:NOW)

    def test_disabled_stops_before_deployment_and_clients(self):
        self.env.clear()
        with patch.object(entry,'load_deployment') as files,patch.object(entry,'_aws_session') as aws:
            with self.assertRaisesRegex(StateError,'disabled'):self.run_entry()
            files.assert_not_called();aws.assert_not_called()

    def test_ticks_cannot_supply_authority_or_select_other_stage(self):
        for event in ({**entry.EVENT,'enabled':True},{**entry.EVENT,'mode':'release'},
                      {**entry.EVENT,'task_id':'other'}):
            with patch.object(entry,'load_deployment') as files:
                with self.subTest(event=event),self.assertRaises(StateError):self.run_entry(event)
                files.assert_not_called()

    def test_alias_and_insufficient_deadline_rejected_before_files(self):
        for change in ('alias','deadline'):
            self.setUp()
            if change=='alias':self.context.invoked_function_arn=self.context.invoked_function_arn[:-1]+'live'
            else:self.context.get_remaining_time_in_millis=lambda:1000
            with patch.object(entry,'load_deployment') as files:
                with self.assertRaises(StateError):self.run_entry()
                files.assert_not_called()

    def test_failed_deployment_redacted_before_cloud_clients(self):
        with patch.object(entry,'load_deployment',side_effect=ValueError('private fixture')), \
                patch.object(entry,'_aws_session') as aws:
            with self.assertRaises(StateError) as caught:self.run_entry()
            self.assertNotIn('private',str(caught.exception));aws.assert_not_called()


if __name__ == '__main__':unittest.main()
