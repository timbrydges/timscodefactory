"""Reproducible Pilot 002-only source and hash-locked Linux verification wheels."""
import base64
import hashlib
import json
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
MODULES=(
    'factory_runtime/pilot002_runtime_probe.py','factory_runtime/pilot002_bootstrap.py',
    'factory_runtime/pilot002_packets.py','factory_runtime/pilot002_authorization.py',
    'factory_runtime/pilot002_attempts.py','factory_runtime/pilot002_protocols.py',
    'factory_runtime/pilot002_transport.py','factory_runtime/pilot002_adapter.py',
    'factory_runtime/pilot002_workflow.py','factory_state/model.py','factory_state/dynamodb.py',
    'factory_state/dispatch.py','factory_state/scope.py','factory_state/signers.py')
MATERIAL=('factory/autonomy/pilot-002-contract.json','factory/evidence/pilot-002-task-budget-approval.json',
    'factory/evidence/pilot-002-baseline-source.json')


def _blob(commit, name):
    return subprocess.check_output(['git','show',commit+':'+name],cwd=ROOT)


def _dependencies(target, lock):
    subprocess.run([sys.executable,'-m','pip','install','--quiet','--require-hashes','--only-binary=:all:',
        '--platform','manylinux_2_34_x86_64','--platform','manylinux_2_28_x86_64',
        '--platform','manylinux2014_x86_64','--python-version','312','--implementation','cp','--abi','cp312',
        '--no-compile','--target',str(target),'-r',str(lock)],check=True)
    # Only inspect the fresh dependency installation, never a user/workspace tree.
    return {p.relative_to(target).as_posix():p.read_bytes() for p in target.rglob('*')
        if p.is_file() and '__pycache__' not in p.parts and p.suffix!='.pyc' and 'bin' not in p.relative_to(target).parts}


def build(output):
    if subprocess.check_output(['git','status','--porcelain'],cwd=ROOT,text=True).strip():
        raise RuntimeError('Pilot 002 package requires clean reviewed source')
    commit=subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip()
    output=Path(output).resolve()
    if output.is_relative_to(ROOT) or output.exists():raise RuntimeError('Use a new output outside checkout')
    with tempfile.TemporaryDirectory(prefix='pilot002-package-') as temporary:
        temporary=Path(temporary);lock=temporary/'requirements.txt'
        lock.write_bytes(_blob(commit,'requirements-role-lambda.txt'))
        files=_dependencies(temporary/'wheels',lock)
        for name in MODULES:files[name]=_blob(commit,'src/'+name)
        for name in MATERIAL:files[name]=_blob(commit,name)
        files.update({'factory_runtime/__init__.py':b'','factory_state/__init__.py':b'',
            'BUILD.json':json.dumps({'source_commit':commit},sort_keys=True).encode(),
            'requirements-role-lambda.txt':lock.read_bytes()})
        index={'source_commit':commit,'files':{name:hashlib.sha256(raw).hexdigest() for name,raw in sorted(files.items())}}
        files['PACKAGE.json']=json.dumps(index,sort_keys=True,separators=(',',':')).encode()
        with zipfile.ZipFile(output,'x',compression=zipfile.ZIP_DEFLATED) as archive:
            for name,raw in sorted(files.items()):
                info=zipfile.ZipInfo(name,(2026,1,1,0,0,0));info.compress_type=zipfile.ZIP_DEFLATED
                info.create_system=3;info.external_attr=0o100644<<16;archive.writestr(info,raw)
    raw_digest=hashlib.sha256(output.read_bytes()).digest()
    return {'source_commit':commit,'sha256':raw_digest.hex(),'code_sha256':base64.b64encode(raw_digest).decode(),
        'zip_bytes':output.stat().st_size,'handler':'factory_runtime.pilot002_runtime_probe.handler',
        'execution_enabled':False,'model_calls':0}


if __name__=='__main__':print(json.dumps(build(sys.argv[1]),indent=2))
