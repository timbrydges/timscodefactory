"""Unattended runner: owner activation gate, no prompts, budget ledger and lock. No network."""
from datetime import datetime, timedelta, timezone
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('unattended', ROOT / 'scripts' / 'unattended_runner.py')
runner = importlib.util.module_from_spec(spec); spec.loader.exec_module(runner)
owner_spec = importlib.util.spec_from_file_location('owner_u', ROOT / 'scripts' / 'run_owner_attempt.py')
owner = importlib.util.module_from_spec(owner_spec); owner_spec.loader.exec_module(owner)

NOW = datetime(2026, 11, 27, 12, tzinfo=timezone.utc)
ENV = {'FACTORY_OPENAI_API_KEY': 'sk-proj-' + 'a' * 40}


def activation(**overrides):
    record = {'kind': 'factory_unattended_activation_v1', 'approved_by': 'tim_brydges',
              'expires_at': (NOW + timedelta(days=7)).isoformat(), 'tasks': ['bonus-library-bulk-covers'],
              'max_usd_per_day': '4.00', 'max_attempts_per_run': 1, 'publish_approved': True,
              'input_price': '1.00', 'output_price': '5.00', 'key_source': 'environment'}
    record.update(overrides)
    return record


class RunnerTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(); self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.calls = []

    def write(self, record):
        (self.root / runner.ACTIVATION).write_text(json.dumps(record))

    def invoke(self, status='APPROVED_AND_PUBLISHED', spent='0.03'):
        def fake(args, env):
            self.calls.append((args, dict(env)))
            return {'status': status, 'spent_usd': spent}
        return fake

    def test_without_the_owner_record_nothing_runs(self):
        result = runner.run_once(self.root, env=ENV, now=NOW, invoke=self.invoke())
        self.assertEqual(result['status'], 'DISABLED')
        self.assertEqual(self.calls, [])

    def test_invalid_or_expired_records_refuse(self):
        for record in (activation(approved_by='someone'), activation(expires_at=(NOW - timedelta(hours=1)).isoformat()),
                       activation(expires_at=(NOW + timedelta(days=60)).isoformat()),
                       activation(max_usd_per_day='50'), activation(tasks=['rm -rf']),
                       dict(activation(), merge=True)):
            with self.subTest(record=record):
                self.write(record)
                with self.assertRaises(ValueError):
                    runner.run_once(self.root, env=ENV, now=NOW, invoke=self.invoke())
        self.assertEqual(self.calls, [])

    def test_one_non_interactive_batch_within_the_daily_budget(self):
        self.write(activation())
        result = runner.run_once(self.root, env=ENV, now=NOW, invoke=self.invoke())
        self.assertEqual(result['status'], 'RAN')
        [(args, env)] = self.calls
        self.assertIn('--non-interactive', args)
        self.assertIn('--publish-approved', args)
        self.assertEqual(args[args.index('--max-total-usd') + 1], '3.75')
        self.assertEqual(env['FACTORY_OPENAI_API_KEY'], ENV['FACTORY_OPENAI_API_KEY'])
        self.assertEqual(result['spent_today_usd'], '0.03')
        self.assertFalse((self.root / runner.LOCK).exists())
        # The ledger carries over: a second run today has only the remainder left.
        result = runner.run_once(self.root, env=ENV, now=NOW, invoke=self.invoke(spent='3.75'))
        self.assertEqual(result['spent_today_usd'], '3.78')
        result = runner.run_once(self.root, env=ENV, now=NOW, invoke=self.invoke())
        self.assertEqual(result['results'], [{'task': 'bonus-library-bulk-covers', 'status': 'BUDGET_REACHED'}])
        self.assertEqual(len(self.calls), 2)
        tomorrow = runner.run_once(self.root, env=ENV, now=NOW + timedelta(days=1), invoke=self.invoke())
        self.assertEqual(tomorrow['spent_today_usd'], '0.03')

    def test_unknown_outcome_counts_at_its_limit_and_stops(self):
        self.write(activation(tasks=['bonus-library-bulk-covers', 'bonus-library-library-archive']))
        def unknown(args, env):
            self.calls.append(args)
            return {'status': 'UNKNOWN_OUTPUT'}
        result = runner.run_once(self.root, env=ENV, now=NOW, invoke=unknown)
        self.assertEqual(result['spent_today_usd'], '3.75')
        self.assertEqual(len(self.calls), 1)

    def test_overlapping_runs_and_missing_keys_never_spend(self):
        self.write(activation())
        (self.root / runner.LOCK).write_text('busy')
        self.assertEqual(runner.run_once(self.root, env=ENV, now=NOW, invoke=self.invoke())['status'],
                         'ALREADY_RUNNING')
        (self.root / runner.LOCK).unlink()
        result = runner.run_once(self.root, env={}, now=NOW, invoke=self.invoke())
        self.assertEqual(result['results'][0]['status'], 'BLOCKED')
        self.assertEqual(self.calls, [])

    def test_secrets_manager_keys_are_read_exactly_and_only_in_memory(self):
        self.write(activation(key_source='aws-secrets-manager'))
        class Client:
            def __init__(self): self.requests = []
            def get_secret_value(self, **kwargs):
                self.requests.append(kwargs)
                return {'SecretString': 'sk-proj-' + 'z' * 40}
        client = Client()
        runner.run_once(self.root, env={}, now=NOW, invoke=self.invoke(), client=client)
        self.assertEqual(client.requests, [{'SecretId': 'tims-software-factory/provider/openai/acceptance',
                                            'VersionStage': 'AWSCURRENT'}])
        self.assertEqual(self.calls[0][1]['FACTORY_OPENAI_API_KEY'], 'sk-proj-' + 'z' * 40)
        self.assertNotIn('zzzz', (self.root / runner.LEDGER).read_text())

    def test_check_reports_blocked_items_with_owner_actions_and_reads_no_secret(self):
        result = runner.check(self.root, env={}, now=NOW, which=lambda name: None,
                              run=lambda *a, **k: type('R', (), {'stdout': ''})())
        self.assertEqual(result['status'], 'BLOCKED')
        self.assertEqual(result['secrets_read'], 0)
        blocked = {i['item']: i['owner_action'] for i in result['items'] if not i['ready']}
        self.assertIn('owner activation record', blocked)
        self.assertIn('docker available', blocked)
        (self.root / 'bonus-source-fetch.json').write_text('{}')
        self.write(activation())
        result = runner.check(self.root, env=ENV, now=NOW, which=lambda name: '/usr/bin/docker',
                              run=lambda *a, **k: type('R', (), {'stdout': ''})())
        self.assertEqual(result['status'], 'READY', result)

    def test_non_interactive_owner_run_never_prompts(self):
        ops = owner.HostOps()
        ops.interactive = False
        with self.assertRaises(ValueError):
            ops.wait_for_key_copy('Anthropic')


if __name__ == '__main__':
    unittest.main()
