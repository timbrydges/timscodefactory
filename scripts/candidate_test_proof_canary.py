"""Produce review-compatible test evidence from the pinned acceptance fixture in Docker."""
import argparse
import asyncio
import hashlib
import json
from pathlib import Path
import re
import sys
import tempfile

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'src'))
from factory_runtime.diagnostics import RedactedDiagnosticCapture
from factory_runtime.docker_sandbox import DockerSandboxAdapter,DockerSandboxPolicy,workspace_tree_digest
from factory_runtime.handoff004_packets import BASELINE,PINNED
from factory_runtime.review_verdict import ReviewBinding,PinnedPythonTestEvidence
from factory_runtime.sandbox import SandboxRequest,validate_sandbox_receipt
from factory_runtime.worker import digest
from factory_state.scope import canonical

COMMAND=('python','-I','-S','-B','-c',
    "import sys,unittest,json; assert sys.version_info[:2]==(3,12); "
    "sys.path.insert(0,'/workspace'); "
    "suite=unittest.defaultTestLoader.discover('/workspace/tests'); "
    "result=unittest.TextTestRunner(verbosity=2).run(suite); "
    "print(json.dumps({'python_version':sys.version.split()[0]})); "
    "sys.exit(0 if result.wasSuccessful() else 1)")


async def run(image_ref,source_commit):
    if not re.fullmatch('[0-9a-f]{40}',source_commit):raise ValueError('Exact source required')
    if not re.fullmatch(r'python@sha256:[0-9a-f]{64}',image_ref):raise ValueError('Immutable Python image required')
    raw=(ROOT/BASELINE).read_bytes()
    if hashlib.sha256(raw).hexdigest()!=PINNED[BASELINE]:raise ValueError('Fixture bytes changed')
    baseline=json.loads(raw);files=baseline['files']
    if set(files)!={'fingerprint.py','tests/test_fingerprint.py'}:raise ValueError('Fixture paths changed')
    with tempfile.TemporaryDirectory(prefix='review-tests-') as directory:
        workspace=Path(directory)
        for name,content in files.items():
            path=workspace/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(content.encode())
        policy=DockerSandboxPolicy(image_ref)
        capture=RedactedDiagnosticCapture(max_chars_per_stream=16384)
        request=SandboxRequest('candidate-test-proof-v1','candidate-test-proof-canary','fixture-qa',
            'qa_engineer',source_commit,workspace_tree_digest(workspace),COMMAND,
            policy.environment_digest,180,policy.runner_identity)
        adapter=DockerSandboxAdapter(workspace,policy,diagnostic_capture=capture)
        receipt=await adapter.execute(request)
        validate_sandbox_receipt(request,receipt)
        logs=capture.take(request,receipt)
        if (logs.redaction_count or logs.stdout_truncated or logs.stderr_truncated or
                digest(logs.stdout_excerpt.encode())!=receipt.stdout_digest or
                digest(logs.stderr_excerpt.encode())!=receipt.stderr_digest):
            raise ValueError('Test diagnostics altered, truncated or redacted')
        metadata=json.loads(logs.stdout_excerpt)
        if set(metadata)!={'python_version'}:raise ValueError('Unexpected test stdout')
        if workspace_tree_digest(workspace)!=request.workspace_digest:raise ValueError('Original candidate changed')
    proof={'source_commit':source_commit,'candidate_commit':baseline['commit'],
        'observed_at':receipt.finished_at.isoformat(),'runtime':'python3.12-linux',
        'python_version':metadata['python_version'],'exit_code':receipt.exit_code,
        'credentials_in_environment':False,'stdout':'','stderr':logs.stderr_excerpt,
        'files':{p:hashlib.sha256(v.encode()).hexdigest() for p,v in files.items()},
        'sandbox':{'image_ref':image_ref,'request_digest':request.request_digest,
            'environment_digest':policy.environment_digest,'workspace_digest':request.workspace_digest,
            'runner_metadata_stdout':logs.stdout_excerpt,'stdout_digest':receipt.stdout_digest,
            'stderr_digest':receipt.stderr_digest,'network':'none','user':policy.user}}
    encoded=canonical(proof)
    binding=ReviewBinding('factory','candidate-test-proof-canary','qa_engineer',source_commit,
        digest(b'non-authoritative canary'),digest(b'fixed acceptance fixture'),baseline['commit'],
        digest(canonical(files)),digest(encoded),tuple(files))
    verifier=PinnedPythonTestEvidence(binding,encoded,files,test_count=17)
    if verifier(binding.candidate_commit,binding.candidate_digest,binding.test_evidence_digest) is not True:
        raise ValueError('Independent test evidence rejected')
    return encoded


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--image-ref',required=True)
    p.add_argument('--source-commit',required=True);p.add_argument('--output',type=Path,required=True)
    args=p.parse_args()
    if args.output.exists():raise ValueError('Evidence output exists')
    evidence=asyncio.run(run(args.image_ref,args.source_commit))
    with args.output.open('xb') as stream:stream.write(evidence)
    print(json.dumps({'status':'ISOLATED_CANDIDATE_TEST_PROOF_VERIFIED','tests':17,
        'proof_digest':digest(evidence),'model_calls':0,'state_writes':0,'gate_authority':False}))
