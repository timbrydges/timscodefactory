import copy
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from factory_runtime import pilot002_repository as p
from factory_state.model import StateError


class RepositoryTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.repo=Path(self.temp.name)
        self.git('init','-q')
        self.files={'fingerprint.py':'# never execute\n','tests/test_fingerprint.py':'# tests\n'}
        self.put('README.md',b'unchanged')
        for name in p.FILES:self.put(name,b'baseline')
        self.baseline=self.commit()
        for name,text in self.files.items():self.put(name,text.encode())
        self.candidate=self.commit(self.baseline)

    def git(self,*args,data=None):
        env={k:v for k,v in os.environ.items() if not k.startswith('GIT_')}
        env.update(GIT_CONFIG_NOSYSTEM='1',GIT_CONFIG_GLOBAL=os.devnull)
        return subprocess.check_output(['git','-c','user.name=Fixture','-c',
            'user.email=fixture@example.invalid','-C',str(self.repo),*args],input=data,env=env).strip()

    def put(self,name,content,mode='100644'):
        oid=self.git('hash-object','-w','--stdin',data=content).decode()
        self.git('update-index','--add','--cacheinfo',mode+','+oid+','+name)

    def commit(self,*parents):
        tree=self.git('write-tree').decode()
        return self.git('commit-tree',tree,*[arg for parent in parents for arg in ('-p',parent)],
            data=b'fixture\n').decode()

    def inspect(self,candidate=None):
        return p._inspect(self.repo,self.baseline,candidate or self.candidate,self.files)

    def test_exact_objects_pass_without_worktree_execution(self):
        (self.repo/'fingerprint.py').write_text('raise RuntimeError("do not run")')
        result=self.inspect()
        self.assertFalse(result['candidate_executed'])
        self.assertEqual(result['candidate_digest'],p.digest(self.files))

    def test_extra_path_rejected_even_from_subdirectory(self):
        self.put('README.md',b'changed')
        candidate=self.commit(self.baseline)
        (self.repo/'subdir').mkdir()
        with self.assertRaises(StateError):
            p._inspect(self.repo/'subdir',self.baseline,candidate,self.files)

    def test_changed_bytes_rejected(self):
        self.put('fingerprint.py',b'# different')
        with self.assertRaises(StateError):self.inspect(self.commit(self.baseline))

    def test_executable_and_symlink_rejected(self):
        for mode in ('100755','120000'):
            with self.subTest(mode=mode):
                self.put('fingerprint.py',self.files['fingerprint.py'].encode(),mode)
                with self.assertRaises(StateError):self.inspect(self.commit(self.baseline))

    def test_missing_file_rejected(self):
        self.git('update-index','--force-remove','fingerprint.py')
        with self.assertRaises(StateError):self.inspect(self.commit(self.baseline))

    def test_oversized_blob_rejected(self):
        self.put('fingerprint.py',b'x'*16385)
        with self.assertRaises(StateError):self.inspect(self.commit(self.baseline))

    def test_root_merge_and_indirect_parent_rejected(self):
        for candidate in (self.commit(),self.commit(self.baseline,self.candidate),self.commit(self.candidate)):
            with self.subTest(candidate=candidate),self.assertRaises(StateError):self.inspect(candidate)

    def test_replacement_cannot_hide_disallowed_change(self):
        self.put('README.md',b'changed')
        bad=self.commit(self.baseline)
        self.git('replace',bad,self.candidate)
        with self.assertRaises(StateError):self.inspect(bad)

    def test_inherited_git_routing_ignored(self):
        with patch.dict(os.environ,{'GIT_DIR':str(self.repo/'missing'),'GIT_WORK_TREE':'missing'}):
            self.inspect()

    def test_invalid_identity_rejected(self):
        for candidate in ('HEAD','--help','A'*40,'a'*39):
            with self.subTest(candidate=candidate),self.assertRaises(StateError):self.inspect(candidate)

    def test_published_binding_and_malformed_observations(self):
        local=self.inspect()
        contract={'baseline_commit':self.baseline,'repository':'owner/repo','branch':'factory/task'}
        parsed={'files':self.files,'builder_response_digest':'sha256:'+'a'*64}
        commit={'sha':self.candidate,'tree':{'sha':local['candidate_tree']},'parents':[{'sha':self.baseline}]}
        ref={'ref':'refs/heads/factory/task','object':{'type':'commit','sha':self.candidate}}
        def verify(c,r):
            seen=[]
            def read(endpoint):
                seen.append(endpoint)
                return c if len(seen)==1 else r
            with patch.object(p,'facts',return_value=(contract,{})),patch.object(p,'parse_builder',return_value=parsed):
                result=p.verify_published_candidate(None,self.repo,builder_response=b'fixture',candidate_commit=self.candidate,github_read=read)
            self.assertEqual(seen,['repos/owner/repo/git/commits/'+self.candidate,'repos/owner/repo/git/ref/heads/factory/task'])
            return result
        self.assertFalse(verify(commit,ref)['gate_authority'])
        for field,value in (('sha','f'*40),('tree',None),('tree',{'sha':'f'*40}),('parents',[None]),('parents',[])):
            changed=copy.deepcopy(commit);changed[field]=value
            with self.subTest(field=field,value=value),self.assertRaises(StateError):verify(changed,ref)
        for field,value in (('ref','refs/heads/other'),('object',None),('object',{'type':'commit','sha':'f'*40})):
            changed=copy.deepcopy(ref);changed[field]=value
            with self.subTest(field=field,value=value),self.assertRaises(StateError):verify(commit,changed)


if __name__=='__main__':unittest.main()
