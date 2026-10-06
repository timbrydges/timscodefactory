"""Authenticate a fresh main-branch Docker test artifact; no Factory state authority."""
import argparse
import base64
import hashlib
import io
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import zipfile

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'src'))
sys.path.insert(0,str(ROOT))
from scripts.candidate_test_proof_canary import COMMAND
from factory_runtime.docker_sandbox import DockerSandboxPolicy
from factory_runtime.sandbox import SandboxRequest
from factory_runtime.handoff004_packets import BASELINE,PINNED
from factory_runtime.review_verdict import ReviewBinding,PinnedPythonTestEvidence
from factory_state.model import StateError
from factory_state.scope import canonical

REPOSITORY='timbrydges/timscodefactory'
WORKFLOW='.github/workflows/runtime-canary.yml'
ARTIFACT='isolated-candidate-test-proof'
MAX_ARCHIVE=131072
MAX_PROOF=65536


def sha(raw):return 'sha256:'+hashlib.sha256(raw).hexdigest()


def verify_sandbox(proof,files,commit):
    try:
        sandbox=proof['sandbox'];image=sandbox['image_ref']
        if not re.fullmatch(r'python@sha256:[0-9a-f]{64}',image):raise ValueError('Image')
        policy=DockerSandboxPolicy(image)
        workspace=sha(b''.join(('F\0'+p+'\0'+'0\0'+hashlib.sha256(v.encode()).hexdigest()+'\n').encode()
            for p,v in sorted(files.items())))
        request=SandboxRequest('candidate-test-proof-v1','candidate-test-proof-canary','fixture-qa',
            'qa_engineer',commit,workspace,COMMAND,policy.environment_digest,180,policy.runner_identity)
        metadata=sandbox['runner_metadata_stdout']
        expected={'image_ref':image,'request_digest':request.request_digest,
            'environment_digest':policy.environment_digest,'workspace_digest':workspace,
            'runner_metadata_stdout':metadata,'stdout_digest':sha(metadata.encode()),
            'stderr_digest':sha(proof['stderr'].encode()),'network':'none','user':policy.user}
        if sandbox!=expected or json.loads(metadata)!={'python_version':proof['python_version']}:
            raise ValueError('Sandbox binding')
    except (KeyError,TypeError,ValueError,AttributeError):raise StateError('Docker test provenance rejected') from None


def verify_metadata(run,artifact,commit,run_id):
    try:
        if (type(run_id)is not int or run_id<=0 or type(commit)is not str or
                re.fullmatch('[0-9a-f]{40}',commit) is None or
                run['id']!=run_id or run['event']!='workflow_dispatch' or run['head_branch']!='main' or
                run['head_sha']!=commit or run['path']!=WORKFLOW or run['status']!='completed' or
                run['conclusion']!='success' or run['repository']['full_name']!=REPOSITORY or
                run['head_repository']['full_name']!=REPOSITORY or
                artifact['name']!=ARTIFACT or artifact['expired'] is not False or
                type(artifact['id'])is not int or artifact['id']<=0 or
                type(artifact['size_in_bytes'])is not int or not 0<artifact['size_in_bytes']<=MAX_ARCHIVE or
                not re.fullmatch('sha256:[0-9a-f]{64}',artifact['digest']) or
                artifact['workflow_run']['id']!=run_id or artifact['workflow_run']['head_sha']!=commit or
                artifact['workflow_run']['head_branch']!='main'):
            raise StateError('Test artifact provenance differs from approved main run')
    except (KeyError,TypeError):raise StateError('Incomplete test artifact provenance') from None


def verify_archive(archive,artifact):
    if (type(archive)is not bytes or len(archive)>MAX_ARCHIVE or
            len(archive)!=artifact['size_in_bytes'] or sha(archive)!=artifact['digest']):
        raise StateError('Test artifact archive differs from GitHub digest')
    try:
        with zipfile.ZipFile(io.BytesIO(archive)) as z:
            entries=z.infolist()
            if (len(entries)!=1 or entries[0].filename!='candidate-test-proof.json' or
                    entries[0].is_dir() or not 0<entries[0].file_size<=MAX_PROOF or
                    entries[0].flag_bits & 1):
                raise StateError('Test artifact archive has unexpected contents')
            return z.read(entries[0])
    except (zipfile.BadZipFile,RuntimeError,ValueError):raise StateError('Invalid test artifact archive') from None


def prepare(commit,run_id,*,api,root=ROOT,clock=None):
    if type(run_id)is not int or run_id<=0 or type(commit)is not str or not re.fullmatch('[0-9a-f]{40}',commit):
        raise StateError('Exact approved source and run ID required')
    prefix='repos/'+REPOSITORY
    head=json.loads(api(prefix+'/git/ref/heads/main'))
    if head.get('object',{}).get('sha')!=commit:raise StateError('Approved source is not current main')
    run=json.loads(api(prefix+'/actions/runs/'+str(run_id)))
    listing=json.loads(api(prefix+'/actions/runs/'+str(run_id)+'/artifacts?per_page=100'))
    matches=[a for a in listing.get('artifacts',[]) if a.get('name')==ARTIFACT]
    if len(matches)!=1 or listing.get('total_count')!=len(listing.get('artifacts',[])):
        raise StateError('Missing, duplicate or incomplete artifact inventory')
    artifact=matches[0];verify_metadata(run,artifact,commit,run_id)
    raw=verify_archive(api(prefix+'/actions/artifacts/'+str(artifact['id'])+'/zip'),artifact)
    baseline_raw=(root/BASELINE).read_bytes()
    if hashlib.sha256(baseline_raw).hexdigest()!=PINNED[BASELINE]:raise StateError('Reviewed candidate fixture changed')
    baseline=json.loads(baseline_raw);files=baseline['files']
    verify_sandbox(json.loads(raw),files,commit)
    binding=ReviewBinding('factory','candidate-test-proof-canary','qa_engineer',commit,
        sha(b'non-authoritative canary'),sha(b'fixed acceptance fixture'),baseline['commit'],
        sha(canonical(files)),sha(raw),tuple(files))
    verifier=PinnedPythonTestEvidence(binding,raw,files,test_count=17,clock=clock)
    if verifier(binding.candidate_commit,binding.candidate_digest,binding.test_evidence_digest) is not True:
        raise StateError('Fresh independent test artifact rejected')
    return {'status':'AUTHENTICATED_MAIN_TEST_PROOF','repository':REPOSITORY,'source_commit':commit,
        'run_id':run_id,'workflow':WORKFLOW,'artifact_id':artifact['id'],'archive_digest':artifact['digest'],
        'proof_digest':sha(raw),'proof_base64':base64.b64encode(raw).decode(),
        'candidate_commit':baseline['commit'],'candidate_digest':binding.candidate_digest,
        'model_calls':0,'state_writes':0,'gate_authority':False}


def github_api(endpoint):
    # Fixed host/repository only. No shell expansion, debug output or provider secret access.
    if not endpoint.startswith('repos/'+REPOSITORY+'/'):raise StateError('Unexpected GitHub route')
    response=subprocess.run(['gh','api','--hostname','github.com',endpoint],
        capture_output=True,timeout=60,env={k:v for k,v in os.environ.items() if k!='GH_DEBUG'})
    if response.returncode or len(response.stdout)>MAX_ARCHIVE:
        raise StateError('Bounded GitHub evidence read failed')
    return response.stdout


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('commit')
    p.add_argument('run_id',type=int);p.add_argument('output',type=Path);args=p.parse_args()
    if args.output.exists():raise StateError('Evidence output already exists')
    result=prepare(args.commit,args.run_id,api=github_api)
    with args.output.open('x',encoding='utf-8') as stream:json.dump(result,stream,indent=2)
    print(json.dumps({k:v for k,v in result.items() if k!='proof_base64'}))
