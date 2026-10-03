"""Reproducible Pilot 002-only source and hash-locked Linux verification wheels."""
import base64
import argparse
import hashlib
import json
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path
from datetime import datetime, timezone

ROOT=Path(__file__).resolve().parents[1]
MODULES=(
    'factory_runtime/pilot002_runtime_probe.py','factory_runtime/pilot002_bootstrap.py',
    'factory_runtime/pilot002_packets.py','factory_runtime/pilot002_authorization.py',
    'factory_runtime/pilot002_attempts.py','factory_runtime/pilot002_protocols.py',
    'factory_runtime/pilot002_transport.py','factory_runtime/pilot002_adapter.py',
    'factory_runtime/pilot002_workflow.py','factory_runtime/pilot002_entrypoint.py','factory_state/model.py','factory_state/dynamodb.py',
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


def _activation(files, raw, now):
    """Validate public deployment material offline; never sign or authorize it."""
    sys.path.insert(0,str(ROOT/'src'))
    from factory_runtime.pilot002_entrypoint import load_activation, ACTIVATION, _pairs
    from factory_runtime.pilot002_adapter import Pilot002Adapter
    from factory_runtime.pilot002_authorization import validate_readiness
    if not isinstance(raw,bytes) or not 0<len(raw)<=131072:raise ValueError('Activation exceeds bound')
    doc=json.loads(raw,object_pairs_hook=_pairs)
    if not isinstance(doc,dict):raise ValueError('Activation object required')
    sha=hashlib.sha256(raw).hexdigest()
    env={'FACTORY_PILOT002_ROLE':doc.get('role'),'FACTORY_PILOT002_ACTIVATION_SHA256':sha}
    with tempfile.TemporaryDirectory(prefix='pilot002-activation-check-') as directory:
        root=Path(directory)
        for name in (*MATERIAL,'BUILD.json'):
            target=root/name;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(files[name])
        (root/ACTIVATION).write_bytes(raw)
        document,context,keys=load_activation(root,env,now)
        adapter=Pilot002Adapter(**context,qualification=document['qualification'],clock=lambda:now,enabled=False)
        price=adapter.pricing
        bindings={k:price[k] for k in ('role','model_id','task_id','source_commit','contract_digest','packet_digest','request_digest')}
        validate_readiness(document['readiness'],bindings=bindings,now=now)
        expires=min(document['qualification']['expires_at'],document['readiness']['expires_at'],
            *(entry['expires_at'] for entry in document['signer_registry']['signers'] if entry['identity'] in keys))
    files[ACTIVATION]=raw
    return {'activation_sha256':sha,'role':doc['role'],'request_digest':bindings['request_digest'],
        'material_expires_at':expires,'signed_allowance_included':False,'activation_authorized':False}


def build(output, *, activation=None, now=None):
    if subprocess.check_output(['git','status','--porcelain'],cwd=ROOT,text=True).strip():
        raise RuntimeError('Pilot 002 package requires clean reviewed source')
    commit=subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip()
    output=Path(output).resolve()
    if output.is_relative_to(ROOT) or output.exists():raise RuntimeError('Use a new output outside checkout')
    activation_raw=None
    if activation is not None:
        with Path(activation).open('rb') as stream:activation_raw=stream.read(131073)
        if not 0<len(activation_raw)<=131072:raise ValueError('Activation exceeds bound')
    activation_info={}
    with tempfile.TemporaryDirectory(prefix='pilot002-package-') as temporary:
        temporary=Path(temporary);lock=temporary/'requirements.txt'
        lock.write_bytes(_blob(commit,'requirements-role-lambda.txt'))
        files=_dependencies(temporary/'wheels',lock)
        for name in MODULES:files[name]=_blob(commit,'src/'+name)
        for name in MATERIAL:files[name]=_blob(commit,name)
        files.update({'factory_runtime/__init__.py':b'','factory_state/__init__.py':b'',
            'BUILD.json':json.dumps({'source_commit':commit},sort_keys=True).encode(),
            'requirements-role-lambda.txt':lock.read_bytes()})
        if activation_raw is not None:
            activation_info=_activation(files,activation_raw,now or datetime.now(timezone.utc))
        index={'source_commit':commit,'files':{name:hashlib.sha256(raw).hexdigest() for name,raw in sorted(files.items())}}
        files['PACKAGE.json']=json.dumps(index,sort_keys=True,separators=(',',':')).encode()
        with zipfile.ZipFile(output,'x',compression=zipfile.ZIP_DEFLATED) as archive:
            for name,raw in sorted(files.items()):
                info=zipfile.ZipInfo(name,(2026,1,1,0,0,0));info.compress_type=zipfile.ZIP_DEFLATED
                info.create_system=3;info.external_attr=0o100644<<16;archive.writestr(info,raw)
    raw_digest=hashlib.sha256(output.read_bytes()).digest()
    return {'source_commit':commit,'sha256':raw_digest.hex(),'code_sha256':base64.b64encode(raw_digest).decode(),
        'zip_bytes':output.stat().st_size,'handler':'factory_runtime.pilot002_runtime_probe.handler',
        'execution_enabled':False,'model_calls':0,**activation_info}


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('output');parser.add_argument('--activation',type=Path)
    args=parser.parse_args()
    print(json.dumps(build(args.output,activation=args.activation),indent=2))
