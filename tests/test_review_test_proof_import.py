from datetime import datetime,timedelta
import io
import json
import unittest
from unittest.mock import Mock
import zipfile

from scripts.prepare_review_test_proof import (prepare,verify_metadata,verify_archive,sha,
    REPOSITORY,WORKFLOW,ARTIFACT,ROOT,verify_sandbox,COMMAND)
from factory_runtime.docker_sandbox import DockerSandboxPolicy
from factory_runtime.sandbox import SandboxRequest
from factory_state.model import StateError


def archive_bytes(files):
    stream=io.BytesIO()
    with zipfile.ZipFile(stream,'w',zipfile.ZIP_DEFLATED) as archive:
        for name,raw in files.items():archive.writestr(name,raw)
    return stream.getvalue()


class TestProofImportTests(unittest.TestCase):
    def setUp(self):
        self.raw=(ROOT/'factory/evidence/handoff-004-live/candidate-python312-proof.json').read_bytes()
        proof=json.loads(self.raw);self.commit=proof['source_commit'];self.now=datetime.fromisoformat(proof['observed_at'])
        files=json.loads((ROOT/'factory/evidence/handoff-004-baseline.json').read_bytes())['files']
        import hashlib
        workspace=sha(b''.join(('F\0'+p+'\0'+'0\0'+hashlib.sha256(v.encode()).hexdigest()+'\n').encode() for p,v in sorted(files.items())))
        policy=DockerSandboxPolicy('python@sha256:'+'a'*64)
        request=SandboxRequest('candidate-test-proof-v1','candidate-test-proof-canary','fixture-qa',
            'qa_engineer',self.commit,workspace,COMMAND,policy.environment_digest,180,policy.runner_identity)
        metadata=json.dumps({'python_version':proof['python_version']})+'\n'
        proof['sandbox']={'image_ref':policy.image_ref,'request_digest':request.request_digest,
            'environment_digest':policy.environment_digest,'workspace_digest':workspace,
            'runner_metadata_stdout':metadata,'stdout_digest':sha(metadata.encode()),
            'stderr_digest':sha(proof['stderr'].encode()),'network':'none','user':policy.user}
        self.files=files;self.proof=proof;self.raw=json.dumps(proof).encode()
        self.archive=archive_bytes({'candidate-test-proof.json':self.raw})
        self.run={'id':123,'event':'workflow_dispatch','head_branch':'main','head_sha':self.commit,
            'path':WORKFLOW,'status':'completed','conclusion':'success',
            'repository':{'full_name':REPOSITORY},'head_repository':{'full_name':REPOSITORY}}
        self.artifact={'id':456,'name':ARTIFACT,'expired':False,'size_in_bytes':len(self.archive),
            'digest':sha(self.archive),'workflow_run':{'id':123,'head_sha':self.commit,'head_branch':'main'}}
        prefix='repos/'+REPOSITORY
        self.responses={prefix+'/git/ref/heads/main':json.dumps({'object':{'sha':self.commit}}).encode(),
            prefix+'/actions/runs/123':json.dumps(self.run).encode(),
            prefix+'/actions/runs/123/artifacts?per_page=100':json.dumps({'total_count':1,'artifacts':[self.artifact]}).encode(),
            prefix+'/actions/artifacts/456/zip':self.archive}
        self.api=Mock(side_effect=lambda path:self.responses[path])
    def test_exact_main_run_imports_bound_proof_without_authority(self):
        result=prepare(self.commit,123,api=self.api,clock=lambda:self.now)
        self.assertEqual(result['proof_digest'],sha(self.raw))
        self.assertFalse(result['gate_authority']);self.assertEqual(result['state_writes'],0)
        self.assertEqual(self.api.call_count,4)
    def test_pull_request_fork_failed_run_and_wrong_source_are_rejected(self):
        for changes in ({'event':'pull_request'},{'head_branch':'feature'},{'head_sha':'a'*40},
                {'conclusion':'failure'},{'status':'in_progress'},{'path':'other.yml'},
                {'head_repository':{'full_name':'other/repository'}}):
            with self.subTest(changes=changes),self.assertRaises(StateError):
                verify_metadata({**self.run,**changes},self.artifact,self.commit,123)
    def test_expired_artifact_wrong_run_and_oversize_rejected(self):
        for changes in ({'expired':True},{'size_in_bytes':131073},{'digest':'bad'},
                {'workflow_run':{'id':999,'head_sha':self.commit,'head_branch':'main'}}):
            with self.subTest(changes=changes),self.assertRaises(StateError):
                verify_metadata(self.run,{**self.artifact,**changes},self.commit,123)
    def test_archive_digest_tampering_and_unexpected_paths_rejected(self):
        with self.assertRaises(StateError):verify_archive(self.archive+b'x',self.artifact)
        for files in ({'../candidate-test-proof.json':self.raw},
                {'candidate-test-proof.json':self.raw,'extra.txt':b'other'},
                {'candidate-test-proof.json':b'x'*65537}):
            raw=archive_bytes(files);artifact={**self.artifact,'size_in_bytes':len(raw),'digest':sha(raw)}
            with self.assertRaises(StateError):verify_archive(raw,artifact)
    def test_stale_proof_and_changed_main_are_rejected(self):
        with self.assertRaises(StateError):prepare(self.commit,123,api=self.api,clock=lambda:self.now+timedelta(hours=2))
        self.responses['repos/'+REPOSITORY+'/git/ref/heads/main']=json.dumps({'object':{'sha':'a'*40}}).encode()
        self.api.reset_mock()
        with self.assertRaises(StateError):prepare(self.commit,123,api=self.api,clock=lambda:self.now)
        self.assertEqual(self.api.call_count,1)
    def test_invalid_request_makes_no_api_call(self):
        for commit,run_id in (('main',123),(self.commit,True),(self.commit,-1)):
            with self.assertRaises(StateError):prepare(commit,run_id,api=self.api)
        self.api.assert_not_called()
    def test_sandbox_network_user_command_and_output_changes_rejected(self):
        verify_sandbox(self.proof,self.files,self.commit)
        for change in ({'network':'host'},{'user':'0:0'},{'request_digest':'sha256:'+'b'*64},
                {'environment_digest':'sha256:'+'b'*64},{'stderr_digest':'sha256:'+'b'*64}):
            with self.subTest(change=change),self.assertRaises(StateError):
                verify_sandbox({**self.proof,'sandbox':{**self.proof['sandbox'],**change}},self.files,self.commit)
