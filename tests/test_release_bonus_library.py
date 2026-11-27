"""Audited release: phrase gate, migration gate, idempotent steps and write-once audit. No network."""
from datetime import datetime, timezone
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('release', ROOT / 'scripts' / 'release_bonus_library.py')
rel = importlib.util.module_from_spec(spec); spec.loader.exec_module(rel)
NOW = datetime(2026, 11, 27, 12, tzinfo=timezone.utc)


def git(cwd, *args):
    return subprocess.run(['git', '-C', str(cwd), '-c', 'user.name=T', '-c', 'user.email=t@example.invalid',
                           '-c', 'commit.gpgsign=false', *args], check=True, capture_output=True, text=True).stdout


class FakeDB:
    def __init__(self, app_commit):
        self.item = {'PK': rel.BUDGET_KEY['PK'], 'SK': rel.BUDGET_KEY['SK'],
                     'app_commit': {'S': app_commit}, 'spent_usd': {'N': '0.42'}}
        self.updates = []

    def get_item(self, **kwargs):
        return {'Item': self.item}

    def update_item(self, **kwargs):
        self.updates.append(kwargs)
        self.item['app_commit'] = kwargs['ExpressionAttributeValues'][':c']


class FakeVercel:
    def __init__(self):
        self.upserts, self.deploys, self.ready = [], [], []

    def ready_production(self, sha):
        return [d for d in self.ready if d['meta']['githubCommitSha'] == sha]

    def upsert_activation(self, sha):
        self.upserts.append(sha)
        return {'created': True}

    def deploy(self, sha):
        self.deploys.append(sha)
        self.ready.append({'uid': 'dpl_1', 'meta': {'githubCommitSha': sha}, 'state': 'READY'})
        return {'id': 'dpl_1', 'url': 'bonus.example'}


class ReleaseTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(); self.addCleanup(tmp.cleanup)
        base = Path(tmp.name)
        seed = base / 'seed'; seed.mkdir()
        git(seed, 'init', '-q', '-b', 'main')
        (seed / 'a.txt').write_text('a'); git(seed, 'add', '.'); git(seed, 'commit', '-qm', 'base')
        self.previous = git(seed, 'rev-parse', 'HEAD').strip()
        (seed / 'supabase/migrations').mkdir(parents=True)
        (seed / 'supabase/migrations/20261113000000_owner_archive.sql').write_text('alter table x;')
        git(seed, 'add', '.')
        git(seed, 'commit', '-qm', 'Archive drafts\n\nFactory attempt library-archive-002; reviewer verdict APPROVE.')
        self.sha = git(seed, 'rev-parse', 'HEAD').strip()
        origin = base / 'origin.git'
        subprocess.run(['git', 'clone', '-q', '--bare', str(seed), str(origin)], check=True)
        self.repo = base / 'clone'
        subprocess.run(['git', 'clone', '-q', str(origin), str(self.repo)], check=True)
        self.audit = base / 'audit'
        self.db, self.vercel = FakeDB(self.previous), FakeVercel()

    def release(self, **overrides):
        options = dict(sha=self.sha, repo=self.repo, approval=rel.phrase_for(self.sha),
                       migrations_applied=['20261113000000_owner_archive.sql'], db=self.db,
                       vercel=self.vercel, audit_dir=self.audit, now=NOW, out=lambda line: None)
        options.update(overrides)
        return rel.release(**options)

    def audits(self):
        return [json.loads(p.read_text()) for p in sorted(self.audit.glob('release-*.json'))]

    def test_dry_run_writes_only_an_audit(self):
        entry = self.release(dry_run=True)
        self.assertEqual(entry['status'], 'DRY_RUN_OK')
        self.assertEqual(entry['steps'], {'budget': 'WOULD_SET', 'activation': 'WOULD_UPSERT',
                                          'deploy': {'status': 'WOULD_DEPLOY'}})
        self.assertEqual((self.db.updates, self.vercel.upserts, self.vercel.deploys), ([], [], []))
        [audit] = self.audits()
        self.assertEqual(audit['reviewer_verdicts'], [{'attempt': 'library-archive-002', 'verdict': 'APPROVE'}])
        self.assertEqual(audit['previous_release'], self.previous)
        self.assertEqual(audit['budget_record'], {'app_commit': self.previous, 'spent_usd': '0.42'})
        self.assertTrue(audit['dry_run'])

    def test_release_runs_each_step_once_and_rerun_is_idempotent(self):
        entry = self.release()
        self.assertEqual(entry['status'], 'RELEASED')
        self.assertEqual(self.db.updates[0]['ConditionExpression'], 'attribute_exists(PK)')
        self.assertEqual((self.vercel.upserts, self.vercel.deploys), ([self.sha], [self.sha]))
        again = self.release(now=NOW.replace(minute=5))
        self.assertEqual(again['steps']['budget'], 'ALREADY_SET')
        self.assertEqual(again['steps']['deploy']['status'], 'ALREADY_READY')
        self.assertEqual((len(self.db.updates), len(self.vercel.deploys)), (1, 1))
        first, second = sorted(self.audit.glob('release-*.json'))
        import hashlib
        self.assertEqual(json.loads(second.read_text())['previous_audit_digest'],
                         'sha256:' + hashlib.sha256(first.read_bytes()).hexdigest())

    def test_gates_stop_before_any_write_and_are_audited(self):
        cases = [dict(approval='Done. Release it'), dict(approval=rel.phrase_for(self.previous)),
                 dict(migrations_applied=[]), dict(sha=self.previous, approval=rel.phrase_for(self.previous)),
                 dict(sha='main', approval=rel.phrase_for('main'))]
        for number, case in enumerate(cases):
            with self.subTest(case=case):
                entry = self.release(now=NOW.replace(second=number), **case)
                self.assertEqual(entry['status'], 'STOPPED')
        self.assertEqual((self.db.updates, self.vercel.upserts, self.vercel.deploys), ([], [], []))
        self.assertEqual(len(self.audits()), len(cases))

    def test_audit_records_are_never_overwritten(self):
        self.release(dry_run=True)
        with self.assertRaises(FileExistsError):
            rel.write_audit({'timestamp': NOW.isoformat(), 'sha': self.sha, 'dry_run': True}, self.audit)


if __name__ == '__main__':
    unittest.main()
