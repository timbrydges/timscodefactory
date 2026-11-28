"""Idea intake: schema, generated acceptance tests that really run, and the approval gate."""
import copy
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))
from factory_runtime import task_intake  # noqa: E402
from factory_state.model import StateError  # noqa: E402

IDEA = {
    'idea_id': 'reading-time',
    'repository': 'timbrydges/bonus-library',
    'target_commit': 'e' * 40,
    'source_manifest_digest': 'sha256:' + 'f' * 64,
    'objective': 'Show an estimated reading time on each library item.',
    'requirements': ['Add readingMinutes(words) in src/lib/reading-time.ts: ceil(words / 200), minimum 1.'],
    'allowed_paths': ['src/lib/reading-time.ts', 'tests/reading-time.test.mjs'],
    'builder_test': 'tests/reading-time.test.mjs',
    'acceptance': [
        {'type': 'exports', 'module': 'src/lib/reading-time.ts', 'names': ['readingMinutes']},
        {'type': 'returns', 'module': 'src/lib/reading-time.ts', 'function': 'readingMinutes',
         'args': [450], 'expect': 3},
        {'type': 'returns', 'module': 'src/lib/reading-time.ts', 'function': 'readingMinutes',
         'args': [0], 'expect': 1},
        {'type': 'source_excludes', 'path': 'src/lib/reading-time.ts', 'text': 'fetch('},
    ],
}
GOOD = 'export function readingMinutes(words: number): number {\n  return Math.max(1, Math.ceil(words / 200));\n}\n'
BAD = 'export function readingMinutes(words: number): number {\n  return Math.round(words / 200);\n}\n'


def node_available():
    return shutil.which('node') is not None


class DraftTests(unittest.TestCase):
    def test_draft_is_pending_and_uses_the_independent_reviewer(self):
        record = task_intake.draft(copy.deepcopy(IDEA))
        task = record['task']
        self.assertEqual(record['status'], 'PENDING_APPROVAL')
        self.assertEqual(task['task_id'], 'bonus-library-reading-time')
        self.assertEqual(task['reviewer_model'], 'claude-opus-5-5')
        self.assertEqual(task['qa_model'], 'gemini-3.8-flash')
        self.assertEqual(task['acceptance_tests'][0]['path'],
                         'tests/factory-acceptance/reading-time.acceptance.test.mjs')
        for flag in ('execution_authorized', 'spending_authorized', 'signing_authorized', 'release_authorized'):
            self.assertIs(task[flag], False)
        self.assertEqual(record['contract_digest'], task_intake.contract_digest(task))
        # Deterministic: the same idea always yields the same contract.
        self.assertEqual(task_intake.draft(copy.deepcopy(IDEA))['contract_digest'], record['contract_digest'])

    def test_malformed_ideas_are_refused(self):
        cases = [
            ('allowed_paths', ['tests/factory-acceptance/x.acceptance.test.mjs', 'tests/reading-time.test.mjs']),
            ('allowed_paths', ['../etc/passwd', 'tests/reading-time.test.mjs']),
            ('builder_test', 'tests/$(rm -rf).test.mjs'),
            ('acceptance', [{'type': 'shell', 'command': 'true'}]),
            ('acceptance', [{'type': 'returns', 'module': 'src/app/page.tsx', 'function': 'f',
                             'args': [], 'expect': 1}]),
            ('acceptance', [{'type': 'source_contains', 'path': 'src/other.ts', 'text': 'x'}]),
            ('target_commit', 'main'),
            ('repository', 'someone/else'),
        ]
        for key, value in cases:
            with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                task_intake.draft({**copy.deepcopy(IDEA), key: value})
        with self.assertRaises(ValueError):
            task_intake.draft({**copy.deepcopy(IDEA), 'execution_authorized': True})

    @unittest.skipUnless(node_available(), 'node is required to run the generated tests')
    def test_generated_acceptance_tests_pass_a_correct_build_and_fail_a_wrong_one(self):
        record = task_intake.draft(copy.deepcopy(IDEA))
        test = record['task']['acceptance_tests'][0]
        for source, expected in ((GOOD, 0), (BAD, 1)):
            with self.subTest(expected=expected), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                (root / 'src/lib').mkdir(parents=True)
                (root / 'src/lib/reading-time.ts').write_text(source)
                (root / test['path']).parent.mkdir(parents=True)
                (root / test['path']).write_text(test['content'])
                run = subprocess.run(['node', '--experimental-strip-types', '--test', test['path']],
                                     cwd=root, capture_output=True, text=True, timeout=60)
                self.assertEqual(run.returncode != 0, bool(expected), run.stdout[-2000:])


class ApprovalTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(); self.addCleanup(tmp.cleanup)
        self.tmp = Path(tmp.name)
        spec = importlib.util.spec_from_file_location('intake_cli', ROOT / 'scripts' / 'task_intake.py')
        self.cli = importlib.util.module_from_spec(spec); spec.loader.exec_module(self.cli)
        (self.tmp / 'idea.json').write_text(json.dumps(IDEA))

    def test_only_the_exact_phrase_approves_and_writes_the_task(self):
        intake, projects = self.tmp / 'intake', self.tmp / 'projects'
        projects.mkdir()
        drafted = self.cli.draft(self.tmp / 'idea.json', intake=intake)
        self.assertEqual(drafted['status'], 'PENDING_APPROVAL')
        task_id = 'bonus-library-reading-time'
        for phrase in ('yes', 'Approve task bonus-library-reading-time', drafted['approval_phrase'] + ' '):
            with self.subTest(phrase=phrase), self.assertRaises(ValueError):
                self.cli.approve(task_id, phrase, intake=intake, projects=projects)
        self.assertFalse((projects / task_id).exists())
        result = self.cli.approve(task_id, drafted['approval_phrase'], intake=intake, projects=projects)
        self.assertEqual(result['status'], 'APPROVED')
        task = json.loads((projects / task_id / 'task.json').read_text())
        record = json.loads((projects / task_id / 'intake.json').read_text())
        self.assertTrue(task_intake.verify_approved(record, task))
        with self.assertRaises(ValueError):  # Already approved; never re-approved or overwritten.
            self.cli.approve(task_id, drafted['approval_phrase'], intake=intake, projects=projects)

    def test_an_edited_contract_loses_its_approval(self):
        record = task_intake.draft(copy.deepcopy(IDEA))
        approved = task_intake.approve(record, phrase=task_intake.approval_phrase(record))
        edited = copy.deepcopy(approved['task'])
        edited['allowed_paths'].append('src/app/dashboard/page.tsx')
        with self.assertRaises(ValueError):
            task_intake.verify_approved(approved, edited)
        tampered = {**record, 'task': edited}
        with self.assertRaises(ValueError):
            task_intake.approve(tampered, phrase=task_intake.approval_phrase(tampered))
        with self.assertRaises(ValueError):
            task_intake.approve(record, phrase=task_intake.approval_phrase(record), owner='someone-else')

    def test_prepare_refuses_a_pending_generated_task(self):
        spec = importlib.util.spec_from_file_location('prep_i', ROOT / 'scripts' / 'prepare_development_attempt.py')
        prep = importlib.util.module_from_spec(spec); spec.loader.exec_module(prep)
        record = task_intake.draft(copy.deepcopy(IDEA))
        folder = self.tmp / 'bonus-library-reading-time'
        folder.mkdir()
        (folder / 'task.json').write_text(json.dumps(record['task']))
        kw = dict(output=self.tmp / 'out', attempt_id='reading-time-001',
                  image_ref='docker.io/library/node@sha256:' + 'a' * 64, source_config_sha256='sha256:' + 'b' * 64,
                  input_price='4.00', output_price='20.00', pricing_source='owner-checked',
                  now=__import__('datetime').datetime.now(__import__('datetime').timezone.utc), hours=12,
                  source_commit='d' * 40, task=folder / 'task.json',
                  reviewer_input_price='4.00', reviewer_output_price='20.00',
                  qa_input_price='4.00', qa_output_price='20.00')
        with self.assertRaises(ValueError):  # No intake record at all.
            prep.prepare(**kw)
        (folder / 'intake.json').write_text(json.dumps(record))
        with self.assertRaises(ValueError):  # Pending, not approved.
            prep.prepare(**kw)
        (folder / 'intake.json').write_text(json.dumps(
            task_intake.approve(record, phrase=task_intake.approval_phrase(record))))
        result = prep.prepare(**kw)
        self.assertEqual(result['status'], 'PREPARED')
        pins = json.loads((self.tmp / 'out' / 'pins.json').read_text())
        self.assertEqual(pins['reviewer_model_id'], 'claude-opus-5-5')
        self.assertEqual(pins['qa_model_id'], 'gemini-3.8-flash')
        self.assertEqual(pins['total_cap'], '3.00')  # (0.50 + 0.25 + 0.25) x 3 rounds


class IntakeCompositionTests(unittest.TestCase):
    def test_generated_task_profile_uses_the_fixed_template_and_its_tests(self):
        from datetime import datetime, timezone
        from types import SimpleNamespace
        from unittest.mock import Mock, patch
        from factory_runtime.development_composition import compose_bonus_host
        task = task_intake.draft(copy.deepcopy(IDEA))['task']
        pins = dict(credential_source='env:FACTORY_OPENAI_API_KEY', model_id='gpt-5.6-sol',
            repository='timbrydges/bonus-library', image_ref='sha256:' + 'b' * 64,
            max_request_bytes=42020, max_output_tokens=16384, builder_cap='0.50', reviewer_cap='0.25',
            total_cap='1.00', reviewer_model_id='claude-opus-5-5',
            reviewer_credential_source='env:FACTORY_ANTHROPIC_API_KEY', qa_model_id='gemini-3.8-flash',
            qa_credential_source='env:FACTORY_GOOGLE_API_KEY', qa_cap='0.25')
        options = dict(approval={}, expected_pins=pins, receipt_path='unused',
            task=SimpleNamespace(task_id=task['task_id'], activation_id='t'),
            contract_bytes=json.dumps(task).encode(), snapshot=None, pricing_source=Mock(),
            clock=lambda: datetime.now(timezone.utc), owner_authorized=True)
        with patch('factory_runtime.development_composition.compose_approved_host') as host:
            compose_bonus_host('unused', **options)
            args = host.call_args.kwargs
        command = args['delivery']['test_command'][2]
        self.assertIn('--test tests/reading-time.test.mjs tests/factory-acceptance/reading-time.acceptance.test.mjs',
                      command)
        self.assertEqual(args['delivery']['required_changed_paths'], sorted(IDEA['allowed_paths']))
        no_reviewer = {k: v for k, v in pins.items() if not k.startswith(('reviewer_m', 'reviewer_c', 'qa_'))}
        with self.assertRaises(StateError):
            compose_bonus_host('unused', **{**options, 'expected_pins': no_reviewer})


if __name__ == '__main__':
    unittest.main()
