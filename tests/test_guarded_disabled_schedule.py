import copy
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
from prepare_disabled_autonomy_schedule import EXPECTED, NAME, TARGET, source, validate_plan


def plan():
    changes = [{'address': address, 'change': {'actions': ['create'], 'after': {}}}
               for address in sorted(EXPECTED)]
    schedule = next(r['change']['after'] for r in changes if 'schedule.autonomy' in r['address'])
    schedule.update({'name': NAME, 'state': 'DISABLED',
        'schedule_expression': 'rate(15 minutes)',
        'schedule_expression_timezone': 'UTC',
        'flexible_time_window': [{'mode': 'OFF'}],
        'target': [{'arn': TARGET, 'input': '{"factory_id":"factory","task_id":"deterministic-text-fingerprint","mode":"acceptance"}',
                    'retry_policy': [{'maximum_retry_attempts': 0,
                                      'maximum_event_age_in_seconds': 60}]}]})
    return {'resource_changes': changes}


class GuardedDisabledScheduleTests(unittest.TestCase):
    def test_only_three_creates_for_disabled_target_pass(self):
        original = plan()
        original['resource_changes'].append({'mode': 'data', 'address': 'data.aws_partition.current',
                                             'change': {'actions': ['read']}})
        validate_plan(original)
        provider_plan = copy.deepcopy(original)
        next(r for r in provider_plan['resource_changes'] if 'schedule.autonomy' in r['address'])[
            'change']['after']['flexible_time_window'][0]['maximum_window_in_minutes'] = None
        validate_plan(provider_plan)
        for mutate in (
                lambda p: p['resource_changes'].append({'address': 'aws_s3_bucket.other',
                                                          'change': {'actions': ['create']}}),
                lambda p: p['resource_changes'][0]['change'].update(actions=['update']),
                lambda p: next(r for r in p['resource_changes'] if 'schedule.autonomy' in r['address'])[
                    'change']['after'].update(state='ENABLED'),
                lambda p: next(r for r in p['resource_changes'] if 'schedule.autonomy' in r['address'])[
                    'change']['after']['target'][0].update(arn=TARGET.removesuffix(':acceptance')),
                lambda p: next(r for r in p['resource_changes'] if 'schedule.autonomy' in r['address'])[
                    'change']['after']['flexible_time_window'][0].update(maximum_window_in_minutes=5)):
            changed = copy.deepcopy(original)
            mutate(changed)
            with self.assertRaises(RuntimeError):
                validate_plan(changed)

    def test_iam_policy_has_stable_name(self):
        terraform = (ROOT / 'infra/aws/autonomy_schedule.tf').read_text()
        self.assertIn('name   = "${local.name_prefix}-autonomy-scheduler-invoke"', terraform)

    def test_source_accepts_only_terraforms_generated_lock(self):
        with patch('prepare_disabled_autonomy_schedule.subprocess.check_output',
                   side_effect=['?? infra/aws/.terraform.lock.hcl\n', 'a' * 40 + '\n']):
            self.assertEqual(source(), 'a' * 40)
        with patch('prepare_disabled_autonomy_schedule.subprocess.check_output',
                   return_value='?? infra/aws/.terraform.lock.hcl\n?? other.json\n'):
            with self.assertRaises(RuntimeError):
                source()


if __name__ == '__main__':
    unittest.main()
