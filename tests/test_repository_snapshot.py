from dataclasses import replace
import asyncio
from datetime import datetime, timezone
import json
from pathlib import Path
import subprocess
from tempfile import TemporaryDirectory
import unittest

from factory_runtime.repository_snapshot import read_repository_snapshot
from factory_runtime.task_candidate import candidate_workspace
from factory_runtime.task_provider import TaskImplementationProtocol
from factory_runtime.task_queue import QueuedTask
from factory_runtime.worker import digest
from factory_state.model import StateError


class RepositorySnapshotTests(unittest.TestCase):
    def setUp(self):
        self.tmp = TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.git('init', '--quiet')
        self.path = 'src/app/(dashboard)/[id]/page.tsx'
        page = self.root / self.path
        page.parent.mkdir(parents=True)
        page.write_bytes(b'const pageSize = 10;\n')
        (self.root/'package.json').write_bytes(b'{"private":true}\n')
        self.git('add', '.')
        self.git('-c', 'user.name=Offline Fixture', '-c', 'user.email=fixture@example.invalid',
                 '-c', 'commit.gpgsign=false', '-c', 'core.hooksPath='+str(self.root/'no-hooks'),
                 'commit', '--quiet', '-m', 'Fixture only')
        self.commit = self.git('rev-parse', 'HEAD').decode().strip()
        self.args = dict(repository='fixture/repo', commit=self.commit)
        self.spec = {'task_id':'task', 'repository':'fixture/repo', 'target_commit':self.commit,
            'allowed_paths':[self.path], 'execution_authorized':False, 'spending_authorized':False,
            'signing_authorized':False, 'release_authorized':False}
        raw = json.dumps(self.spec).encode()
        self.protocol = TaskImplementationProtocol(QueuedTask('entry','factory','task','activation',
            'a'*40,digest(raw),'IMPLEMENTATION'), repository='fixture/repo', target_commit=self.commit,
            contract_bytes=raw, files={self.path:'const pageSize = 10;\n'})
        self.decision = {'type':'apply_edits','summary':'Fixture change',
            'edits':[{'path':self.path,'old_text':'10','new_text':'20'}]}

    def git(self, *args, input=None):
        return subprocess.run(['git','-C',str(self.root),*args],input=input,check=True,
                              stdout=subprocess.PIPE,stderr=subprocess.PIPE).stdout

    def test_uses_pinned_objects_not_dirty_or_untracked_files(self):
        (self.root/self.path).write_bytes(b'dirty checkout')
        (self.root/'.env').write_bytes(b'not source')
        snapshot = read_repository_snapshot(self.root, **self.args)
        self.assertEqual(len(snapshot.files),2)
        self.assertEqual({f.path:f.content for f in snapshot.files}[self.path],b'const pageSize = 10;\n')
        with candidate_workspace(self.protocol,self.decision,repository_snapshot=snapshot) as candidate:
            directory = candidate.workspace
            self.assertEqual((directory/self.path).read_bytes(),b'const pageSize = 20;\n')
            self.assertEqual((directory/'package.json').read_bytes(),b'{"private":true}\n')
            self.assertFalse((directory/'.env').exists())
        self.assertFalse(directory.exists())
        self.assertEqual((self.root/self.path).read_bytes(),b'dirty checkout')

    def test_wrong_repository_or_target_rejected(self):
        snapshot = read_repository_snapshot(self.root, **self.args)
        for bad in [replace(snapshot,repository='other/repo'),replace(snapshot,commit='b'*40)]:
            with self.assertRaises(StateError):
                with candidate_workspace(self.protocol,self.decision,repository_snapshot=bad):
                    self.fail('must reject')

    def test_stale_provider_context_rejected(self):
        snapshot = read_repository_snapshot(self.root, **self.args)
        changed = tuple(replace(f,content=b'other') if f.path==self.path else f for f in snapshot.files)
        with self.assertRaises(StateError):
            with candidate_workspace(self.protocol,self.decision,
                                     repository_snapshot=replace(snapshot,files=changed)):
                self.fail('must reject')

    def test_missing_commit_does_not_fetch(self):
        self.git('remote','add','origin','https://invalid.example/no-network')
        with self.assertRaises(StateError):
            read_repository_snapshot(self.root, **{**self.args,'commit':'b'*40})

    def test_symlink_tree_rejected_without_materialization(self):
        oid = self.git('hash-object','-w','--stdin',input=b'../outside').decode().strip()
        self.git('update-index','--add','--cacheinfo','120000,'+oid+',link')
        tree = self.git('write-tree').decode().strip()
        commit = self.git('-c','user.name=Fixture','-c','user.email=f@example.invalid',
                         '-c','commit.gpgsign=false','commit-tree',tree,input=b'Fixture link\n').decode().strip()
        with self.assertRaises(StateError):
            read_repository_snapshot(self.root,repository='fixture/repo',commit=commit)

    def test_executable_mode_is_retained_in_snapshot(self):
        self.git('update-index','--chmod=+x',self.path)
        tree = self.git('write-tree').decode().strip()
        commit = self.git('-c','user.name=Fixture','-c','user.email=f@example.invalid',
                         '-c','commit.gpgsign=false','commit-tree',tree,input=b'Mode fixture\n').decode().strip()
        snapshot = read_repository_snapshot(self.root,repository='fixture/repo',commit=commit)
        self.assertTrue(next(f for f in snapshot.files if f.path==self.path).executable)

    def test_complete_candidate_uses_existing_isolated_adapter_offline(self):
        from factory_runtime.docker_sandbox import DockerSandboxAdapter, DockerSandboxPolicy, ProcessResult
        from test_docker_sandbox import FakeRunner, IMAGE, CONTAINER_ID
        snapshot = read_repository_snapshot(self.root, **self.args)
        policy = DockerSandboxPolicy(image_ref=IMAGE)
        runner = FakeRunner(ProcessResult(0,b'image'), ProcessResult(0,CONTAINER_ID.encode()),
                            ProcessResult(0,b'fixture only'), ProcessResult(0,b'0'), ProcessResult(0))
        with candidate_workspace(self.protocol,self.decision,repository_snapshot=snapshot) as candidate:
            request = candidate.request(request_id='fixture',lease_id='fixture',role_id='builder',
                command=('node','--test'),environment_digest=policy.environment_digest,
                timeout_seconds=30,expected_runner_identity=policy.runner_identity)
            receipt = asyncio.run(DockerSandboxAdapter(candidate.workspace,policy,
                                  process_runner=runner).execute(request))
            result = candidate.evaluate(request,receipt,now=datetime.now(timezone.utc))
            self.assertEqual(result['status'],'TESTS_PASSED_REVIEW_REQUIRED')
            self.assertFalse(result['progression_authorized'])
        self.assertIn('--network=none',runner.calls[1][0])
        self.assertIn('--pull=never',runner.calls[1][0])
        self.assertEqual(len(runner.calls),5)

    def test_submodule_tree_rejected(self):
        self.git('update-index','--add','--cacheinfo','160000,'+self.commit+',submodule')
        tree = self.git('write-tree').decode().strip()
        commit = self.git('-c','user.name=Fixture','-c','user.email=f@example.invalid',
                         '-c','commit.gpgsign=false','commit-tree',tree,input=b'Submodule fixture\n').decode().strip()
        with self.assertRaises(StateError):
            read_repository_snapshot(self.root,repository='fixture/repo',commit=commit)

    def test_replacement_objects_cannot_change_pinned_source(self):
        original = self.git('rev-parse',self.commit+':'+self.path).decode().strip()
        other = self.git('hash-object','-w','--stdin',input=b'replaced source').decode().strip()
        self.git('replace',original,other)
        snapshot = read_repository_snapshot(self.root,**self.args)
        self.assertEqual(next(f.content for f in snapshot.files if f.path==self.path),b'const pageSize = 10;\n')


if __name__ == '__main__': unittest.main()
