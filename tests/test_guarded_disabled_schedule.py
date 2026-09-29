import copy
import json
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
from prepare_disabled_autonomy_schedule import (
    ACCOUNT, EXPECTED, GROUP_SOURCE, NAME, OLD_SCHEDULE_SOURCE,
    ROLE_ADDRESS, SCHEDULE, TARGET, assert_existing_iam, source, validate_plan,
    updates_schedule,
)


def plan():
    changes = [{'address': address, 'change': {'actions': ['create'], 'after': {}}}
               for address in sorted(EXPECTED)]
    next(r['change']['after'] for r in changes if r['address'] == ROLE_ADDRESS)[
        'assume_role_policy'] = trust(GROUP_SOURCE)
    schedule = next(r['change']['after'] for r in changes if 'schedule.autonomy' in r['address'])
    schedule.update({'name': NAME, 'state': 'DISABLED',
        'schedule_expression': 'rate(15 minutes)',
        'schedule_expression_timezone': 'UTC',
        'flexible_time_window': [{'mode': 'OFF'}],
        'target': [{'arn': TARGET, 'input': '{"factory_id":"tims-software-factory","task_id":"deterministic-text-fingerprint","mode":"acceptance"}',
                    'retry_policy': [{'maximum_retry_attempts': 0,
                                      'maximum_event_age_in_seconds': 60}]}]})
    return {'resource_changes': changes}


def trust(source_arn):
    return json.dumps({'Version': '2012-10-17', 'Statement': [{
        'Effect': 'Allow', 'Principal': {'Service': 'scheduler.amazonaws.com'},
        'Action': 'sts:AssumeRole',
        'Condition': {'StringEquals': {'aws:SourceAccount': ACCOUNT},
                      'ArnEquals': {'aws:SourceArn': source_arn}},
    }]})


class GuardedDisabledScheduleTests(unittest.TestCase):
    def test_exact_existing_disabled_input_update_only(self):
        change = copy.deepcopy(next(r for r in plan()['resource_changes']
                                    if r['address'] == SCHEDULE))
        change['change']['actions'] = ['update']
        change['change']['before'] = copy.deepcopy(change['change']['after'])
        change['change']['before']['target'][0]['input'] = (
            '{"factory_id":"factory","task_id":"deterministic-text-fingerprint","mode":"acceptance"}')
        update = {'resource_changes': [change]}
        self.assertEqual(validate_plan(update), {SCHEDULE})
        self.assertTrue(updates_schedule(update))
        for mutate in (
            lambda p: p['resource_changes'][0]['change']['before']['target'][0].update(
                input='{"factory_id":"other"}'),
            lambda p: p['resource_changes'][0]['change']['after'].update(state='ENABLED'),
            lambda p: p['resource_changes'][0]['change']['after']['target'][0].update(
                arn=TARGET.removesuffix(':acceptance')),
            lambda p: p['resource_changes'][0]['change'].update(replace_paths=[['target']]),
        ):
            invalid = copy.deepcopy(update)
            mutate(invalid)
            with self.subTest(mutate=mutate), self.assertRaises(RuntimeError):
                validate_plan(invalid)

    def test_only_exact_disabled_schedule_creates_pass(self):
        original = plan()
        original['resource_changes'].append({'mode': 'data', 'address': 'data.aws_partition.current',
                                             'change': {'actions': ['read']}})
        validate_plan(original)
        provider_plan = copy.deepcopy(original)
        next(r for r in provider_plan['resource_changes'] if 'schedule.autonomy' in r['address'])[
            'change']['after']['flexible_time_window'][0]['maximum_window_in_minutes'] = None
        validate_plan(provider_plan)
        schedule_only = copy.deepcopy(original)
        schedule_only['resource_changes'] = [r for r in schedule_only['resource_changes']
                                             if r['address'] == SCHEDULE]
        self.assertEqual(validate_plan(schedule_only), {SCHEDULE})
        missing_policy = copy.deepcopy(original)
        missing_policy['resource_changes'] = [r for r in missing_policy['resource_changes']
                                              if r['address'] != 'aws_iam_role_policy.autonomy_scheduler_invoke[0]']
        with self.assertRaises(RuntimeError):
            validate_plan(missing_policy)
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

    def test_schedule_only_requires_existing_exact_iam(self):
        iam = sorted(EXPECTED - {SCHEDULE})
        with patch('prepare_disabled_autonomy_schedule.terraform', return_value='\n'.join(iam)), \
                patch('prepare_disabled_autonomy_schedule.assert_scheduler_iam') as verify_iam:
            assert_existing_iam()
            verify_iam.assert_called_once_with(GROUP_SOURCE)
        with patch('prepare_disabled_autonomy_schedule.terraform', return_value=iam[0]):
            with self.assertRaises(RuntimeError):
                assert_existing_iam()
        with patch('prepare_disabled_autonomy_schedule.terraform', return_value='\n'.join([*iam, SCHEDULE])):
            with self.assertRaises(RuntimeError):
                assert_existing_iam()

    def test_iam_policy_has_stable_name(self):
        terraform = (ROOT / 'infra/aws/autonomy_schedule.tf').read_text()
        self.assertIn('name   = "${local.name_prefix}-autonomy-scheduler-invoke"', terraform)
        self.assertIn('schedule-group/default', terraform)

    def test_only_exact_trust_update_and_disabled_schedule_pass(self):
        changed = plan()
        changed['resource_changes'] = [r for r in changed['resource_changes']
                                       if r['address'] == SCHEDULE]
        role = {'address': ROLE_ADDRESS, 'change': {'actions': ['update'],
                'before': {'name': 'tims-software-factory-autonomy-scheduler',
                           'assume_role_policy': trust(OLD_SCHEDULE_SOURCE)},
                'after': {'name': 'tims-software-factory-autonomy-scheduler',
                          'assume_role_policy': trust(GROUP_SOURCE)}}}
        changed['resource_changes'].append(role)
        self.assertEqual(validate_plan(changed), {SCHEDULE, ROLE_ADDRESS})
        for field, value in (('name', 'other-role'),
                             ('assume_role_policy', trust('arn:aws:scheduler:other:group/*'))):
            invalid = copy.deepcopy(changed)
            invalid['resource_changes'][1]['change']['after'][field] = value
            with self.assertRaises(RuntimeError):
                validate_plan(invalid)
        invalid = copy.deepcopy(changed)
        invalid['resource_changes'][1]['change']['actions'] = ['delete', 'create']
        with self.assertRaises(RuntimeError):
            validate_plan(invalid)

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
