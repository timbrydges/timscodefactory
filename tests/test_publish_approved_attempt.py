import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

from factory_state.scope import canonical
from factory_runtime.worker import digest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('publish_attempt', ROOT/'scripts'/'publish_approved_attempt.py')
pub = importlib.util.module_from_spec(spec); spec.loader.exec_module(pub)


def run(cwd, *args):
    return subprocess.run(['git', '-C', str(cwd), '-c', 'user.name=T', '-c', 'user.email=t@example.invalid',
                           '-c', 'commit.gpgsign=false', *args], check=True, capture_output=True, text=True).stdout


class PublishTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(); self.addCleanup(tmp.cleanup)
        self.base = Path(tmp.name).resolve()
        seed = self.base/'seed'; seed.mkdir()
        run(seed, 'init', '-q', '-b', 'main')
        (seed/'src').mkdir(); (seed/'src'/'page.tsx').write_text('const size = 10;\n')
        run(seed, 'add', '.'); run(seed, 'commit', '-qm', 'base')
        self.commit = run(seed, 'rev-parse', 'HEAD').strip()
        self.origin = self.base/'origin.git'
        subprocess.run(['git', 'clone', '-q', '--bare', str(seed), str(self.origin)], check=True)
        self.proposal = {'type': 'apply_edits', 'summary': 'Page', 'edits': []}
        self.changes = [{'path': 'src/page.tsx', 'before': 'const size = 10;\n', 'after': 'const size = 20;\n'},
                        {'path': 'tests/page.test.mjs', 'before': None, 'after': 'test\n'}]
        self.attempt = self.base/'attempt'; self.attempt.mkdir()
        self.write()
        outer = self
        class LocalGit(pub.Git):
            def __call__(self, *args, capture=False):
                args = [str(outer.origin) if a.startswith('https://github.com/') else a for a in args]
                return subprocess.run(['git', '-C', str(self.directory), '-c', 'user.name=Owner',
                    '-c', 'user.email=owner@example.invalid', '-c', 'commit.gpgsign=false',
                    '-c', 'core.autocrlf=false', *args], check=True, text=True,
                    capture_output=capture).stdout
        self.git = LocalGit

    def write(self, **overrides):
        packet = {'kind': 'factory_task_review_v1', 'repository': 'timbrydges/bonus-library',
                  'target_commit': self.commit, 'specification': {'objective': 'Browse older items'},
                  'candidate_decision_digest': digest(canonical(self.proposal)), 'changes': self.changes}
        packet.update(overrides.pop('packet', {}))
        review = digest(canonical(packet))
        decision = {'review_input_digest': review, 'verdict': overrides.pop('verdict', 'APPROVE'), 'findings': []}
        artifact = {'kind': 'development_attempt_v1', 'proposal': self.proposal,
                    'review_packet': {**packet, 'review_input_digest': review}, 'review_decision': decision,
                    'result': {'status': 'REVIEW_ACCEPTED', 'review_input_digest': review,
                               'review_decision_digest': digest(canonical(decision))},
                    'authoritative': False, 'release_authorized': False}
        artifact.update(overrides)
        self.raw = json.dumps(artifact).encode()
        (self.attempt/'attempt.json').write_bytes(self.raw)

    def publish(self, results=None):
        work = tempfile.mkdtemp(dir=self.base)
        return pub.publish(attempt_dir=self.attempt, attempt_id='pagination-005', results_file=results,
                           workdir=work, git_factory=self.git, out=lambda line: None)

    def test_pushes_exact_approved_contents_to_new_branch_only(self):
        result = self.publish()
        self.assertEqual(result['branch'], 'factory/pagination-005')
        self.assertIn('/compare/', result['url'])
        tree = run(self.origin, 'show', 'factory/pagination-005:src/page.tsx')
        self.assertEqual(tree, 'const size = 20;\n')
        self.assertEqual(run(self.origin, 'show', 'factory/pagination-005:tests/page.test.mjs'), 'test\n')
        self.assertEqual(run(self.origin, 'rev-parse', 'main').strip(), self.commit)
        self.assertIn('reviewer verdict APPROVE', run(self.origin, 'log', '-1', '--format=%B', 'factory/pagination-005'))

    def test_contract_acceptance_tests_are_published_unchanged(self):
        content = "import test from 'node:test';\n"
        self.write(packet={'specification': {'objective': 'Browse', 'acceptance_tests': [
            {'path': 'tests/factory-acceptance/a.test.mjs', 'content': content}]}})
        self.publish()
        self.assertEqual(run(self.origin, 'show', 'factory/pagination-005:tests/factory-acceptance/a.test.mjs'), content)

    def test_existing_branch_is_never_overwritten(self):
        self.publish()
        with self.assertRaises(ValueError):
            self.publish()

    def test_unapproved_or_tampered_artifacts_never_clone(self):
        cases = [dict(verdict='REJECT'), dict(packet={'repository': 'other/repo'}),
                 dict(release_authorized=True), dict(packet={'changes': [{'path': '../x', 'before': None, 'after': 'x'}]})]
        for case in cases:
            with self.subTest(case=case):
                self.write(**case)
                with self.assertRaises(ValueError):
                    self.publish()
        self.write()
        artifact = json.loads(self.raw); artifact['review_packet']['changes'][0]['after'] = 'evil\n'
        (self.attempt/'attempt.json').write_text(json.dumps(artifact))
        with self.assertRaises(ValueError):
            self.publish()
        self.assertEqual(run(self.origin, 'branch', '--list', 'factory/*').strip(), '')

    def test_recorded_result_digest_must_match(self):
        results = self.base/'result.json'
        results.write_text(json.dumps({'outcome': {'status': 'TICK_COMPLETED', 'result': {'artifact_digest': 'sha256:' + '0'*64}}}))
        with self.assertRaises(ValueError):
            self.publish(results)
        results.write_text(json.dumps({'outcome': {'status': 'TICK_COMPLETED', 'result': {'artifact_digest': digest(self.raw)}}}))
        self.assertEqual(self.publish(results)['status'], 'PUSHED')

    def test_changed_base_file_stops_before_push(self):
        self.changes[0]['before'] = 'something else\n'
        self.write()
        with self.assertRaises(ValueError):
            self.publish()
        self.assertEqual(run(self.origin, 'branch', '--list', 'factory/*').strip(), '')

    def test_cli_requires_owner_authorization(self):
        import contextlib, io
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            pub.main(['--attempt-id', 'pagination-005'])


if __name__ == '__main__':
    unittest.main()
