from datetime import datetime, timezone
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('run_owner_attempt', ROOT/'scripts'/'run_owner_attempt.py')
owner = importlib.util.module_from_spec(spec); spec.loader.exec_module(owner)

KEY = 'sk-proj-' + 'A1b2_C3-' * 6


class FakeOps:
    def __init__(self, base):
        self.base, self.events = base, []
        self.clipboard, self.total, self.dirty = KEY, 200 * 1024 * 1024, False
        self.journal = {'builder.completed.json': {'cost_usd': '0.13', 'proposal': {'type': 'apply_edits', 'summary': 'Add pagination'}},
                        'reviewer.completed.json': {'cost_usd': '0.03', 'proposal': {'verdict': 'REJECT', 'findings': ['Type not inferred']}},
                        'repair_builder.completed.json': {'cost_usd': '0.12', 'proposal': {'type': 'apply_edits', 'summary': 'Typed rows'}},
                        'repair_reviewer.completed.json': {'cost_usd': '0.03', 'proposal': {'verdict': 'APPROVE', 'findings': []}}}
        self.status = 'TICK_COMPLETED'

    def factory_head(self): self.events.append('head'); return 'f'*40, self.dirty
    def volume_total(self, path): self.events.append('volume'); return self.total
    def docker_image_digest(self, image): self.events.append('docker'); return 'node@sha256:' + 'a'*64
    def wait_for_key_copy(self): self.events.append('prompt')
    def read_clipboard(self): self.events.append('clipboard'); return self.clipboard + '\r\n'
    def clear_clipboard(self): self.events.append('clear')

    def run_attempt(self, args, env):
        self.events.append('run')
        self.env_key = env['FACTORY_OPENAI_API_KEY']
        self.args = args
        directory = Path(args[args.index('--attempt-directory') + 1])
        directory.mkdir()
        for name, data in self.journal.items():
            (directory/name).write_text(json.dumps(data))
        return json.dumps({'entry_id': directory.name, 'status': self.status}) + '\n'


class OwnerAttemptTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(); self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name).resolve()
        (self.root/'source-attempts').mkdir()
        raw = json.dumps(dict(schema=1, app_client_id='Iv23offlineOnly', installation_id=77,
            repository='timbrydges/bonus-library', repository_id=1375052827,
            git_executable=str(self.root/'git'), signer_executable=str(self.root/'openssl'),
            key_path=str(self.root/'k.pem'), public_fingerprint='SHA256:'+'A'*43+'=',
            attempt_parent=str(self.root/'source-attempts'))).encode()
        (self.root/'bonus-source-fetch.json').write_bytes(raw)
        self.ops = FakeOps(self.root)
        self.lines = []
        owner.os.environ.pop('FACTORY_OPENAI_API_KEY', None)

    def run_owner(self, **kw):
        args = dict(runner_root=self.root, attempt_id=None, repair_rounds=1, input_price='4.00',
                    output_price='20.00', pricing_source='owner-checked', image='node:22-slim',
                    manifest=owner.PINNED_MANIFEST, hours=12, ops=self.ops, out=self.lines.append,
                    now=datetime(2026, 11, 1, tzinfo=timezone.utc))
        args.update(kw)
        return owner.run(**args)

    def test_one_command_prepares_loads_key_runs_once_and_summarizes(self):
        summary = self.run_owner()
        self.assertEqual(self.ops.events, ['head', 'volume', 'docker', 'prompt', 'clipboard', 'clear', 'run'])
        self.assertEqual(self.ops.env_key, KEY)
        self.assertEqual(summary['attempt_id'], 'pagination-001')
        self.assertEqual(summary['total_cost_usd'], '0.31')
        self.assertEqual(summary['stages']['repair_reviewer']['verdict'], 'APPROVE')
        pins = json.loads((self.root/'dev-inputs'/'pagination-001'/'pins.json').read_text())
        self.assertEqual((pins['repair_rounds'], pins['total_cap']), (1, '1.50'))
        written = (self.root/'dev-results'/'pagination-001.json').read_text()
        self.assertNotIn(KEY, written)
        self.assertFalse(any(KEY in line for line in self.lines))
        self.assertIn('Type not inferred', '\n'.join(self.lines))

    def test_next_attempt_id_skips_used_names(self):
        for name in ('pagination-001', 'pagination-004', 'pagination-002.consumed.json'):
            folder = self.root/'dev-attempts'; folder.mkdir(exist_ok=True)
            (folder/name).mkdir() if not name.endswith('.json') else (folder/name).write_text('{}')
        self.assertEqual(owner.next_attempt_id(self.root/'dev-attempts', self.root/'dev-inputs'), 'pagination-005')
        self.assertEqual(self.run_owner()['attempt_id'], 'pagination-005')

    def test_bad_clipboard_stops_before_running(self):
        self.ops.clipboard = 'Remove-Item Env:FACTORY_OPENAI_API_KEY'
        with self.assertRaises(ValueError) as caught:
            self.run_owner()
        self.assertNotIn('run', self.ops.events)
        self.assertIn('clear', self.ops.events)
        self.assertNotIn('Remove-Item', str(caught.exception))

    def test_preflight_failures_stop_before_preparation_or_key(self):
        for change, message in (({'dirty': True}, 'local changes'), ({'total': 500 * 1024**3}, 'not attached')):
            with self.subTest(change=change):
                ops = FakeOps(self.root); ops.__dict__.update(change); self.ops = ops
                with self.assertRaises(ValueError) as caught:
                    self.run_owner()
                self.assertIn(message, str(caught.exception))
                self.assertNotIn('prompt', ops.events)
        self.assertFalse((self.root/'dev-inputs').exists())

    def test_cli_requires_owner_authorization(self):
        import contextlib, io
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            owner.main(['--input-price', '4', '--output-price', '20'], ops=self.ops)
        self.assertEqual(self.ops.events, [])

    def test_failed_attempt_returns_nonzero(self):
        self.ops.status = 'REJECTED'
        self.assertEqual(owner.main(['--owner-authorized', '--runner-root', str(self.root),
            '--input-price', '4.00', '--output-price', '20.00'], ops=self.ops), 1)


if __name__ == '__main__':
    unittest.main()
