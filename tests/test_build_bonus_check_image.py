import importlib.util
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('build_image', ROOT/'scripts'/'build_bonus_check_image.py')
image = importlib.util.module_from_spec(spec); spec.loader.exec_module(image)


class BuildImageTests(unittest.TestCase):
    def setUp(self):
        self.calls = []
        def runner(args):
            self.calls.append(args)
            if args[:2] == ['git', 'clone']:
                Path(args[-1]).mkdir()
            if 'show' in args:
                return '{"name":"bonus-library"}' if args[-1].endswith('package.json') else '{"lockfileVersion":3}'
            if args[:3] == ['docker', 'image', 'inspect']:
                return 'sha256:' + 'c'*64 + '\n'
            return ''
        self.runner = runner

    def test_builds_from_exact_commit_lock_and_pinned_base(self):
        with tempfile.TemporaryDirectory() as work:
            result = image.build(commit=image.PINNED_COMMIT, base=image.PINNED_BASE, workdir=work,
                                 runner=self.runner, out=lambda line: None)
            dockerfile = (Path(work)/'context'/'Dockerfile').read_text()
        self.assertEqual(result, {'tag': 'factory-bonus-checks:ef88df95bc3f', 'image_id': 'sha256:' + 'c'*64})
        self.assertIn(f'FROM {image.PINNED_BASE}', dockerfile)
        self.assertIn('npm ci --ignore-scripts', dockerfile)
        shows = [c[-1] for c in self.calls if 'show' in c]
        self.assertEqual(shows, [f'{image.PINNED_COMMIT}:package.json', f'{image.PINNED_COMMIT}:package-lock.json'])
        self.assertIn(['docker', 'build', '--pull=false', '-t', 'factory-bonus-checks:ef88df95bc3f'],
                      [c[:5] for c in self.calls])

    def test_unpinned_inputs_do_nothing(self):
        for kw in ({'commit': 'main'}, {'base': 'node:22-slim'}):
            with self.subTest(kw=kw), tempfile.TemporaryDirectory() as work, self.assertRaises(ValueError):
                image.build(**{'commit': image.PINNED_COMMIT, 'base': image.PINNED_BASE, **kw},
                            workdir=work, runner=self.runner, out=lambda line: None)
        self.assertEqual(self.calls, [])

    def test_cli_requires_owner_authorization(self):
        import contextlib, io
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            image.main([], runner=self.runner)
        self.assertEqual(self.calls, [])


if __name__ == '__main__':
    unittest.main()
