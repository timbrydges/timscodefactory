import base64
import json
import sys
import tempfile
import unittest
from datetime import timedelta
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / 'src'), str(ROOT / 'scripts'), str(ROOT / 'tests')]
import activate_acceptance_schedule as schedule
from test_activate_acceptance_component import material


class ScheduleActivationTests(unittest.TestCase):
    def test_one_delivery_uses_exact_target_no_retries_and_no_repeat_expression(self):
        binding, raw, now, _ = material()
        plan = {'binding': binding, 'job_base64': base64.b64encode(raw).decode()}
        request = schedule.schedule_request(plan, run_at=now + timedelta(minutes=3), now=now)
        self.assertTrue(request['ScheduleExpression'].startswith('at('))
        self.assertEqual(request['Target']['Arn'], schedule.TARGET)
        self.assertEqual(json.loads(request['Target']['Input']), schedule.INPUT)
        self.assertEqual(request['Target']['RetryPolicy'], {'MaximumRetryAttempts': 0, 'MaximumEventAgeInSeconds': 60})
        self.assertEqual(request['ActionAfterCompletion'], 'NONE')

    def test_expiring_signatures_or_too_soon_delivery_prevent_scheduling(self):
        binding, raw, now, _ = material()
        plan = {'binding': binding, 'job_base64': base64.b64encode(raw).decode()}
        for delta in (timedelta(seconds=30), timedelta(minutes=15), timedelta(hours=1)):
            with self.subTest(delta=delta), self.assertRaisesRegex(RuntimeError, 'insufficient fresh scope'):
                schedule.schedule_request(plan, run_at=now + delta, now=now)

    def test_uncertain_activation_never_repeats_mutation(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'schedule.json'
            path.write_text(json.dumps({'status': 'ATTEMPTED_RECONCILE_REQUIRED'}))
            with patch.object(schedule, 'aws') as aws, self.assertRaisesRegex(RuntimeError, 'single-attempt'):
                schedule.execute(path)
            aws.assert_not_called()

    def test_reconcile_only_reads_and_rejects_changed_target(self):
        binding, raw, now, _ = material()
        request = schedule.schedule_request({'binding': binding, 'job_base64': base64.b64encode(raw).decode()},
            run_at=now + timedelta(minutes=3), now=now)
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'schedule.json'
            path.write_text(json.dumps({'status': 'ATTEMPTED_RECONCILE_REQUIRED', 'request': request}))
            bad = {**request, 'State': 'DISABLED'}
            with patch.object(schedule, 'aws', side_effect=[{'Account': schedule.ACCOUNT}, bad]) as aws:
                with self.assertRaisesRegex(RuntimeError, 'do not resubmit'):
                    schedule.reconcile(path)
                self.assertEqual([call.args[:2] for call in aws.call_args_list],
                    [('sts', 'get-caller-identity'), ('scheduler', 'get-schedule')])


if __name__ == '__main__':
    unittest.main()
