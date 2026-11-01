import contextlib
import hashlib
import io
import json
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'scripts'))
import private_source_fetch as entry
from factory_runtime.repository_snapshot import RepositoryFile, RepositorySnapshot
from factory_runtime.private_source import snapshot_manifest_digest

COMMIT = 'ef88df95bc3f046d080af51e3654d2259759072b'


class EntrypointTests(unittest.TestCase):
    def setUp(self):
        tmp = TemporaryDirectory(); self.addCleanup(tmp.cleanup)
        base = Path(tmp.name).resolve()
        (base/'attempts').mkdir()
        raw = json.dumps(dict(schema=1, app_client_id='Iv23offlineOnly', installation_id=77,
            repository='owner/private', repository_id=123, git_executable=str(base/'git'),
            signer_executable=str(base/'openssl'), key_path=str(base/'k.pem'),
            public_fingerprint='SHA256:'+'A'*43+'=', attempt_parent=str(base/'attempts'))).encode()
        self.config = base/'source.json'; self.config.write_bytes(raw)
        self.digest = 'sha256:'+hashlib.sha256(raw).hexdigest()
        self.snapshot = RepositorySnapshot('owner/private', COMMIT,
                                           (RepositoryFile('a.txt', b'abc', False),))
        self.manifest = snapshot_manifest_digest(self.snapshot)

    def args(self, *extra):
        return ['--fetch-once', '--owner-authorized', '--config', str(self.config),
                '--config-sha256', self.digest, '--commit', COMMIT,
                '--manifest', self.manifest, '--attempt-name', 'first-fetch', *extra]

    def run_main(self, argv):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = entry.main(argv)
        return code, json.loads(out.getvalue())

    def test_default_is_disabled_without_acquisition(self):
        with patch.object(entry.composition, 'acquire_private_source') as acquire:
            self.assertEqual(self.run_main([]), (0, {'status': 'DISABLED', 'source_requests': 0}))
        acquire.assert_not_called()

    def test_missing_authorization_or_pins_refused(self):
        full = self.args()
        for drop in ('--owner-authorized', '--commit', '--manifest', '--attempt-name'):
            argv = [a for i, a in enumerate(full) if a != drop and
                    not (i > 0 and full[i-1] == drop and drop != '--owner-authorized')]
            with self.subTest(drop=drop), patch.object(entry.composition,
                    'acquire_private_source') as acquire, \
                    contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                entry.main(argv)
            acquire.assert_not_called()

    def test_one_authorized_acquisition_with_exact_binding(self):
        with patch.object(entry.composition, 'acquire_private_source',
                          return_value=self.snapshot) as acquire:
            code, result = self.run_main(self.args())
        self.assertEqual(code, 0)
        config, binding, name = acquire.call_args.args
        self.assertEqual((binding.repository, binding.repository_id, binding.commit,
                          binding.manifest_digest), ('owner/private', 123, COMMIT, self.manifest))
        self.assertEqual(name, 'first-fetch')
        self.assertIs(acquire.call_args.kwargs['enabled'], True)
        self.assertEqual(acquire.call_count, 1)
        self.assertEqual((result['status'], result['files'], result['bytes'], result['manifest']),
                         ('VERIFIED', 1, 3, self.manifest))

    def test_wrong_config_digest_stops_before_acquisition(self):
        argv = self.args(); argv[argv.index(self.digest)] = 'sha256:'+'0'*64
        with patch.object(entry.composition, 'acquire_private_source') as acquire, \
                self.assertRaises(Exception):
            entry.main(argv)
        acquire.assert_not_called()

    def test_cli_failure_reports_type_only(self):
        result = subprocess.run([sys.executable, str(ROOT/'scripts'/'private_source_fetch.py'),
            *self.args()[:-1], 'Bad/Name'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(json.loads(result.stdout)['status'], 'STOPPED')
        self.assertNotIn(b'Bad/Name', result.stdout)


if __name__ == '__main__':
    unittest.main()
