from dataclasses import replace
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import subprocess
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import Mock, patch

from factory_runtime.private_source import (SourceBinding, InstallationLease,
    GitHubObjectFetch, fetch_private_snapshot, snapshot_manifest_digest,
    validate_installation_response)
from factory_runtime.repository_snapshot import RepositorySnapshot, RepositoryFile
from factory_state.model import StateError


class PrivateSourceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve() / 'attempt'
        self.now = datetime(2026, 10, 20, tzinfo=timezone.utc)
        self.snapshot = RepositorySnapshot('owner/private', 'a'*40,
            (RepositoryFile('src/page.ts', b'const pageSize=10;', False),))
        self.binding = SourceBinding('owner/private', 123, 'a'*40, snapshot_manifest_digest(self.snapshot))
        self.token = 'fake-offline-secret-token'
        self.response = dict(token=self.token, expires_at=(self.now+timedelta(minutes=59)).isoformat(),
            permissions={'contents':'read','metadata':'read'}, repositories=[{'id':123,'full_name':'owner/private'}])
        self.issue = Mock(side_effect=lambda **kw: dict(self.response))
        self.revoke = Mock(return_value=True)
        self.fetch = Mock()
        self.read = Mock(return_value=self.snapshot)

    def execute(self, **changes):
        args = dict(binding=self.binding, issue_token=self.issue, revoke_token=self.revoke,
                    fetch_objects=self.fetch, read_snapshot=self.read, clock=lambda:self.now,
                    enabled=True, owner_authorized=True)
        args.update(changes)
        return fetch_private_snapshot(self.root, **args)

    def receipt(self):
        return json.loads((self.root/'source-fetch.json').read_text())

    def test_disabled_and_missing_authorization_have_no_effect(self):
        for change in ({'enabled':False},{'owner_authorized':False},{'enabled':1}):
            with self.assertRaises(StateError): self.execute(**change)
        self.issue.assert_not_called(); self.assertFalse(self.root.exists())

    def test_verified_snapshot_is_usable_by_existing_candidate_contract(self):
        from factory_runtime.task_candidate import candidate_workspace
        from factory_runtime.task_provider import TaskImplementationProtocol
        from factory_runtime.task_queue import QueuedTask
        from factory_runtime.worker import digest
        snapshot = self.execute()
        spec = dict(task_id='task', repository='owner/private', target_commit='a'*40,
                    allowed_paths=['src/page.ts'], execution_authorized=False,
                    spending_authorized=False, signing_authorized=False, release_authorized=False)
        raw = json.dumps(spec).encode()
        protocol = TaskImplementationProtocol(QueuedTask('entry','factory','task','activation',
            'b'*40,digest(raw),'IMPLEMENTATION'), repository='owner/private',target_commit='a'*40,
            contract_bytes=raw, files={'src/page.ts':'const pageSize=10;'})
        decision = dict(type='apply_edits',summary='offline fixture',
                        edits=[dict(path='src/page.ts',old_text='10',new_text='20')])
        with candidate_workspace(protocol,decision,repository_snapshot=snapshot) as candidate:
            self.assertEqual((candidate.workspace/'src/page.ts').read_bytes(),b'const pageSize=20;')
        self.assertFalse(candidate.workspace.exists())
        self.assertFalse((self.root/'objects').exists())
        self.assertEqual(self.receipt()['status'],'VERIFIED')
        self.revoke.assert_called_once_with(self.token)
        self.issue.assert_called_once_with(repository_ids=[123],permissions={'contents':'read','metadata':'read'})

    def test_attempt_directory_cannot_be_reused(self):
        self.execute()
        with self.assertRaises(FileExistsError): self.execute()
        self.issue.assert_called_once(); self.fetch.assert_called_once()

    def test_real_local_git_objects_flow_through_existing_snapshot_reader(self):
        from factory_runtime.repository_snapshot import read_repository_snapshot
        fixture = Path(self.tmp.name)/'fixture'
        fixture.mkdir()
        def git(*args):
            return subprocess.run(['git','-C',str(fixture),*args],check=True,
                stdout=subprocess.PIPE,stderr=subprocess.PIPE).stdout
        git('init','--quiet')
        (fixture/'page.txt').write_bytes(b'original source')
        git('add','page.txt')
        git('-c','user.name=Offline Fixture','-c','user.email=fixture@example.invalid',
            '-c','commit.gpgsign=false','-c','core.hooksPath='+str(fixture/'absent-hooks'),
            'commit','--quiet','-m','Offline fixture')
        commit = git('rev-parse','HEAD').decode().strip()
        expected = read_repository_snapshot(fixture,repository='owner/private',commit=commit)
        binding = replace(self.binding,commit=commit,manifest_digest=snapshot_manifest_digest(expected))
        def local_transfer(destination,*args):
            # No remote or HTTP: transfer only the fixture's local object store.
            import shutil
            shutil.copytree(fixture/'.git',destination/'.git')
        actual = self.execute(binding=binding,fetch_objects=local_transfer,read_snapshot=read_repository_snapshot)
        self.assertEqual(actual,expected)
        self.assertFalse((self.root/'objects').exists())

    def test_missing_scope_evidence_does_not_fetch(self):
        del self.response['repositories']
        with self.assertRaises(StateError): self.execute()
        self.fetch.assert_not_called(); self.revoke.assert_called_once()

    def test_unconfirmed_revocation_stops(self):
        self.revoke.return_value = None
        with self.assertRaises(StateError): self.execute()
        self.assertFalse(self.receipt()['revocation_confirmed'])

    def test_wrong_scope_missing_scope_and_permissions_rejected_and_revoked(self):
        changes = [dict(repositories=[]),dict(repositories=[{'id':124,'full_name':'owner/private'}]),
                   dict(repositories=[{'id':123,'full_name':'other/repo'}]),
                   dict(repositories=self.response['repositories']*2),
                   dict(permissions={'contents':'write','metadata':'read'}),
                   dict(permissions={'contents':'read','metadata':'read','actions':'read'})]
        for number, change in enumerate(changes):
            with self.subTest(change=change):
                self.root = self.root.parent / f'scope-{number}'
                original = dict(self.response); self.response.update(change)
                with self.assertRaises(StateError): self.execute()
                self.response = original
                self.assertTrue(self.receipt()['revocation_confirmed'])
        self.fetch.assert_not_called()

    def test_expired_short_and_excessive_lifetime_rejected(self):
        for seconds in (-1,60,3601):
            response = dict(self.response,expires_at=(self.now+timedelta(seconds=seconds)).isoformat())
            with self.assertRaises(StateError): validate_installation_response(response,self.binding,self.now)

    def test_no_fixed_token_length_and_no_secret_repr(self):
        response = dict(self.response,token='ghs_'+('x'*2000))
        lease = validate_installation_response(response,self.binding,self.now)
        self.assertNotIn(response['token'],repr(lease))

    def test_lease_expiry_between_issue_and_fetch_stops(self):
        times = iter([self.now,self.now+timedelta(hours=1)])
        with self.assertRaises(StateError): self.execute(clock=lambda:next(times))
        self.fetch.assert_not_called(); self.revoke.assert_called_once()

    def test_issuance_uncertainty_is_durable_and_not_retried(self):
        self.issue.side_effect = RuntimeError(self.token)
        with self.assertRaises(StateError) as error: self.execute()
        self.assertNotIn(self.token,str(error.exception))
        self.assertEqual(self.receipt()['status'],'STOPPED_NEEDS_RECONCILIATION')
        with self.assertRaises(FileExistsError): self.execute()
        self.issue.assert_called_once(); self.fetch.assert_not_called()

    def test_fetch_failure_cleans_partial_objects_and_redacts(self):
        def failed(path,*args):
            (path/'partial').write_text('partial objects')
            raise RuntimeError(self.token)
        self.fetch.side_effect = failed
        with self.assertRaises(StateError): self.execute()
        self.assertFalse((self.root/'objects').exists())
        self.assertNotIn(self.token,(self.root/'source-fetch.json').read_text())
        self.revoke.assert_called_once()

    def test_wrong_commit_and_manifest_rejected(self):
        for number, value in enumerate((replace(self.snapshot,commit='b'*40),
                replace(self.snapshot,files=(RepositoryFile('src/page.ts',b'changed',False),)))):
            self.root = self.root.parent / f'tree-{number}'
            self.read.return_value = value
            with self.assertRaises(StateError): self.execute()
            self.assertTrue(self.receipt()['object_cleanup'])

    def test_revocation_failure_never_releases_snapshot(self):
        self.revoke.side_effect = RuntimeError(self.token)
        with self.assertRaises(StateError): self.execute()
        self.assertFalse(self.receipt()['revocation_confirmed'])
        self.assertTrue(self.receipt()['object_cleanup'])

    def test_cleanup_failure_never_releases_snapshot(self):
        with patch('factory_runtime.private_source.shutil.rmtree',side_effect=OSError('busy')):
            with self.assertRaises(StateError): self.execute()
        self.assertFalse(self.receipt()['object_cleanup'])

    def test_invalid_binding_stops_before_issuance(self):
        for change in (dict(repository='x/../bad'),dict(repository_id=True),dict(commit='main'),dict(manifest_digest='none')):
            with self.assertRaises(StateError): self.execute(binding=replace(self.binding,**change))
        self.issue.assert_not_called()

    def test_git_transport_default_disabled(self):
        run=Mock()
        transport=GitHubObjectFetch(Path(self.tmp.name)/'git.exe',run=run)
        with self.assertRaises(StateError): transport(self.root,self.binding,InstallationLease(self.token,self.now))
        run.assert_not_called()

    def test_git_transport_contains_credentials_only_in_fetch_child_environment(self):
        self.root.mkdir()
        calls=[]
        def run(args,**kwargs): calls.append((list(args),dict(kwargs['env']),kwargs['timeout']))
        transport=GitHubObjectFetch(Path(self.tmp.name)/'git.exe',enabled=True,run=run)
        with patch.dict('os.environ',{'OPENAI_API_KEY':'owner-secret','GIT_CONFIG_COUNT':'99','GIT_TRACE':'1'}):
            transport(self.root,self.binding,InstallationLease(self.token,self.now))
        self.assertEqual(len(calls),2)
        self.assertNotIn('GIT_CONFIG_VALUE_0',calls[0][1])
        self.assertIn('Authorization: Basic ',calls[1][1]['GIT_CONFIG_VALUE_0'])
        for args,env,timeout in calls:
            self.assertNotIn(self.token,' '.join(args)); self.assertNotIn('OPENAI_API_KEY',env)
            self.assertNotIn('GIT_TRACE',env); self.assertEqual(timeout,60)
        self.assertIn('https://github.com/owner/private.git',calls[1][0])
        self.assertIn(self.binding.commit,calls[1][0])
        self.assertNotIn('remote',calls[1][0]); self.assertNotIn('checkout',calls[1][0])

    def test_git_fetch_error_is_not_retried_and_child_env_is_cleared(self):
        self.root.mkdir(); retained=[]
        def run(args,**kwargs):
            retained.append(kwargs['env'])
            if 'fetch' in args: raise subprocess.TimeoutExpired(self.token,60)
        transport=GitHubObjectFetch(Path(self.tmp.name)/'git.exe',enabled=True,run=run)
        with self.assertRaises(StateError) as error:
            transport(self.root,self.binding,InstallationLease(self.token,self.now))
        self.assertEqual(len(retained),2); self.assertEqual(retained[-1],{})
        self.assertNotIn(self.token,str(error.exception))
