"""Build only an inert recovery package from clean tracked source and locked wheels."""
import base64
import hashlib
import json
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

from build_pilot002_runtime_package import MODULES as SHARED_MODULES,MATERIAL as SHARED_MATERIAL,_dependencies

ROOT=Path(__file__).resolve().parents[1]
MODULES=(*SHARED_MODULES,'factory_runtime/inspector_recovery001.py',
    'factory_runtime/inspector_recovery001_authorization.py',
    'factory_runtime/inspector_recovery001_runtime.py','factory_runtime/inspector_recovery001_entrypoint.py')
MATERIAL=(*SHARED_MATERIAL,'factory/autonomy/inspector-recovery-001-scope.json')
HANDLER='factory_runtime.inspector_recovery001_entrypoint.handler'


def _blob(commit,name):
    return subprocess.check_output(['git','show',commit+':'+name],cwd=ROOT)


def build(output):
    if subprocess.check_output(['git','status','--porcelain'],cwd=ROOT,text=True).strip():
        raise RuntimeError('Recovery package requires clean reviewed source')
    commit=subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip()
    output=Path(output).resolve()
    if output.is_relative_to(ROOT) or output.exists():raise RuntimeError('Use a new output outside checkout')
    with tempfile.TemporaryDirectory(prefix='inspector-recovery001-package-') as directory:
        temporary=Path(directory);lock=temporary/'requirements.txt'
        lock.write_bytes(_blob(commit,'requirements-role-lambda.txt'))
        files=dict(_dependencies(temporary/'wheels',lock))
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
    sha=hashlib.sha256(output.read_bytes()).digest()
    return {'source_commit':commit,'sha256':sha.hex(),'code_sha256':base64.b64encode(sha).decode(),
        'zip_bytes':output.stat().st_size,'handler':HANDLER,'execution_enabled':False,
        'activation_included':False,'signed_allowance_included':False,'model_calls':0}


if __name__=='__main__':print(json.dumps(build(sys.argv[1]),indent=2))
