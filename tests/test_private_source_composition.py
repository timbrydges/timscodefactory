from datetime import datetime, timedelta, timezone
import base64
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
from tempfile import TemporaryDirectory
import unittest

from factory_runtime.private_source import SourceBinding, snapshot_manifest_digest
from factory_runtime.private_source_composition import (
    acquire_private_source, read_private_source_configuration)
from factory_runtime.repository_snapshot import read_repository_snapshot
from factory_state.model import StateError

PUBLIC = b'offline-fake-public-key-der'
FINGERPRINT = 'SHA256:' + base64.b64encode(hashlib.sha256(PUBLIC).digest()).decode()
TOKEN = 'ghs_offlineFakeInstallationToken'


class FakeConnection:
    def __init__(self, log, owner):
        self.log, self.owner = log, owner

    def __call__(self, host, timeout):
        self.log.append(('connect', host, timeout))
        return self

    def request(self, method, path, body=None, headers=None):
        self.log.append(('http', method, path, body, headers['Authorization']))
        if self.owner.http_error:
            raise OSError('offline secret-bearing failure')
        self.method = method

    def getresponse(self):
        owner = self.owner
        class Response:
            status = 201 if self.method == 'POST' else 204
            def read(_, limit):
                return json.dumps(owner.response).encode() if self.method == 'POST' else b''
        return Response()

    def close(self):
        pass


class CompositionTests(unittest.TestCase):
    def setUp(self):
        tmp = TemporaryDirectory(); self.addCleanup(tmp.cleanup)
        self.base = Path(tmp.name).resolve()
        self.now = datetime(2026, 10, 31, tzinfo=timezone.utc)
        for name in ('openssl', 'git', 'app.pem'):
            (self.base/name).write_bytes(b'offline placeholder, never executed')
        (self.base/'attempts').mkdir()
        self.fixture = self.base/'fixture'; self.fixture.mkdir()
        git = lambda *a: subprocess.run(['git', '-C', str(self.fixture), *a], check=True,
                                        stdout=subprocess.PIPE, stderr=subprocess.PIPE).stdout
        git('init', '--quiet')
        (self.fixture/'page.txt').write_bytes(b'private source')
        git('add', 'page.txt')
        git('-c', 'user.name=Offline', '-c', 'user.email=offline@example.invalid',
            '-c', 'commit.gpgsign=false', '-c', 'core.hooksPath='+os.devnull,
            'commit', '--quiet', '-m', 'fixture')
        commit = git('rev-parse', 'HEAD').decode().strip()
        expected = read_repository_snapshot(self.fixture, repository='owner/private', commit=commit)
        self.expected = expected
        self.binding = SourceBinding('owner/private', 123, commit, snapshot_manifest_digest(expected))
        self.data = dict(schema=1, app_client_id='Iv23offlineOnly', installation_id=77,
            repository='owner/private', repository_id=123, git_executable=str(self.base/'git'),
            signer_executable=str(self.base/'openssl'), key_path=str(self.base/'app.pem'),
            public_fingerprint=FINGERPRINT, attempt_parent=str(self.base/'attempts'))
        self.log = []
        self.http_error = False
        self.public = PUBLIC
        self.response = dict(token=TOKEN, expires_at=(self.now+timedelta(minutes=59)).isoformat(),
            permissions={'contents': 'read', 'metadata': 'read'},
            repositories=[{'id': 123, 'full_name': 'owner/private'}])

    def config(self, **changes):
        raw = json.dumps(dict(self.data, **changes)).encode()
        path = self.base/'source.json'; path.write_bytes(raw)
        return read_private_source_configuration(
            path, 'sha256:'+hashlib.sha256(raw).hexdigest(), owner_authorized=True)

    def receipt(self, name='attempt-1'):
        return json.loads((self.base/'attempts'/name/'source-fetch.json').read_text())

    def fake_run(self, args, **kwargs):
        if Path(args[0]).name == 'openssl':
            state = self.receipt()
            self.log.append(('sign', args[1], state['issuance_started']))
            out = self.public if args[1] == 'rsa' else b's'*256
        else:
            command = next(a for a in args[1:] if a in ('init', 'fetch'))
            self.log.append(('git', command, kwargs['env'].get('GIT_CONFIG_VALUE_0')))
            if command == 'fetch':
                shutil.copytree(self.fixture/'.git', Path(args[args.index('-C')+1])/'.git')
            out = b''
        return subprocess.CompletedProcess(args, 0, stdout=out)

    def acquire(self, config=None, name='attempt-1', **changes):
        args = dict(clock=lambda: self.now, enabled=True, owner_authorized=True,
                    run=self.fake_run, connection=FakeConnection(self.log, self))
        args.update(changes)
        return acquire_private_source(config or self.config(), self.binding, name, **args)

    def test_configuration_is_strictly_pinned(self):
        raw = json.dumps(self.data).encode(); path = self.base/'c.json'; path.write_bytes(raw)
        digest = 'sha256:'+hashlib.sha256(raw).hexdigest()
        with self.assertRaises(StateError):
            read_private_source_configuration(path, digest)
        with self.assertRaises(StateError):
            read_private_source_configuration(path, 'sha256:'+'0'*64, owner_authorized=True)
        for bad in (dict(self.data, extra=1), dict(self.data, schema=2),
                    dict(self.data, installation_id='77'), dict(self.data, key_path='app.pem'),
                    dict(self.data, attempt_parent=str(self.base)),
                    dict(self.data, public_fingerprint='SHA256:short')):
            with self.subTest(bad=bad), self.assertRaises(StateError):
                raw = json.dumps(bad).encode(); path.write_bytes(raw)
                read_private_source_configuration(path, 'sha256:'+hashlib.sha256(raw).hexdigest(),
                                                  owner_authorized=True)
        raw = b'{"schema":1,"schema":1}'; path.write_bytes(raw)
        with self.assertRaises(StateError):
            read_private_source_configuration(path, 'sha256:'+hashlib.sha256(raw).hexdigest(),
                                              owner_authorized=True)

    def test_disabled_or_mismatched_binding_has_no_effect(self):
        config = self.config()
        for change in ({'enabled': False}, {'owner_authorized': False}, {'enabled': 1}):
            with self.assertRaises(StateError): self.acquire(config, **change)
        other = SourceBinding('owner/other', 123, self.binding.commit, self.binding.manifest_digest)
        with self.assertRaises(StateError):
            acquire_private_source(config, other, 'attempt-1', clock=lambda: self.now,
                                   enabled=True, owner_authorized=True, run=self.fake_run)
        with self.assertRaises(StateError): self.acquire(config, name='../escape')
        self.assertEqual(self.log, [])
        self.assertEqual(list((self.base/'attempts').iterdir()), [])

    def test_end_to_end_offline_sequence_reserves_before_signing(self):
        snapshot = self.acquire()
        self.assertEqual(snapshot, self.expected)
        kinds = [(e[0], e[1]) for e in self.log if e[0] != 'connect']
        self.assertEqual(kinds, [('sign', 'rsa'), ('sign', 'dgst'), ('http', 'POST'),
                                 ('git', 'init'), ('git', 'fetch'), ('http', 'DELETE')])
        self.assertTrue(all(e[2] is True for e in self.log if e[0] == 'sign'))
        post = next(e for e in self.log if e[:2] == ('http', 'POST'))
        self.assertEqual(post[2], '/app/installations/77/access_tokens')
        self.assertEqual(json.loads(post[3]), {'repository_ids': [123],
            'permissions': {'contents': 'read', 'metadata': 'read'}})
        self.assertEqual(len(post[4].split('.')), 3)
        self.assertNotIn(TOKEN, post[4])
        self.assertIsNone(self.log[[e[:2] for e in self.log].index(('git', 'init'))][2])
        delete = next(e for e in self.log if e[:2] == ('http', 'DELETE'))
        self.assertEqual(delete[4], 'Bearer '+TOKEN)
        receipt = (self.base/'attempts'/'attempt-1'/'source-fetch.json').read_text()
        self.assertEqual(json.loads(receipt)['status'], 'VERIFIED')
        self.assertNotIn(TOKEN, receipt)
        self.assertFalse((self.base/'attempts'/'attempt-1'/'objects').exists())

    def test_fingerprint_mismatch_stops_before_issuance_and_cannot_retry(self):
        self.public = b'different-public-key'
        with self.assertRaises(StateError): self.acquire()
        self.assertEqual([e[0] for e in self.log], ['sign'])
        self.assertEqual(self.receipt()['status'], 'STOPPED_NEEDS_RECONCILIATION')
        self.public = PUBLIC
        with self.assertRaises(FileExistsError): self.acquire()
        self.assertEqual(len(self.log), 1)

    def test_uncertain_issuance_is_not_retried_or_fetched(self):
        self.http_error = True
        with self.assertRaises(StateError) as caught: self.acquire()
        self.assertNotIn('secret', str(caught.exception))
        self.assertEqual([e[1] for e in self.log if e[0] == 'http'], ['POST'])
        self.assertFalse(any(e[0] == 'git' for e in self.log))
        receipt = self.receipt()
        self.assertEqual((receipt['status'], receipt['issuance_started'], receipt['fetch_started']),
                         ('STOPPED_NEEDS_RECONCILIATION', True, False))

    def test_fetched_content_mismatch_is_revoked_and_stopped(self):
        (self.fixture/'page.txt').write_bytes(b'tampered')
        subprocess.run(['git', '-C', str(self.fixture), '-c', 'user.name=x', '-c',
            'user.email=x@example.invalid', '-c', 'commit.gpgsign=false', 'commit', '-qam', 'x'],
            check=True, stdout=subprocess.DEVNULL)
        self.binding = SourceBinding('owner/private', 123,
            subprocess.run(['git', '-C', str(self.fixture), 'rev-parse', 'HEAD'], check=True,
                           stdout=subprocess.PIPE).stdout.decode().strip(),
            self.binding.manifest_digest)
        with self.assertRaises(StateError): self.acquire()
        self.assertEqual(self.log[-1][:2], ('http', 'DELETE'))
        receipt = self.receipt()
        self.assertEqual((receipt['status'], receipt['revocation_confirmed'], receipt['object_cleanup']),
                         ('STOPPED_NEEDS_RECONCILIATION', True, True))


if __name__ == '__main__':
    unittest.main()
