"""Add only committed public observation evidence to the locked runtime package."""
import hashlib
import base64
import json
from pathlib import Path
import subprocess
import tempfile
import zipfile
from build_handoff002_package import build as runtime,ROOT


def build(output):
    output=Path(output).resolve()
    if output.exists() or output.is_relative_to(ROOT):raise ValueError('New external output required')
    with tempfile.TemporaryDirectory() as temporary:
        package=Path(temporary)/'runtime.zip';meta=runtime(package)
        with zipfile.ZipFile(package) as z:files={n:z.read(n) for n in z.namelist() if n!='PACKAGE.json'}
    names=['scripts/observe_handoff002_controller.py','scripts/verify_handoff002_saved_evidence.py',
        'factory/profiles/scope-signers.json']
    names+=subprocess.check_output(['git','ls-tree','-r','--name-only',meta['source_commit'],
        'factory/evidence/handoff-002-live'],cwd=ROOT,text=True).splitlines()
    for name in names:
        files[name]=subprocess.check_output(['git','show',meta['source_commit']+':'+name],cwd=ROOT)
    files['PACKAGE.json']=json.dumps({'source_commit':meta['source_commit'],
        'files':{n:hashlib.sha256(b).hexdigest() for n,b in sorted(files.items())}},sort_keys=True).encode()
    with zipfile.ZipFile(output,'x',compression=zipfile.ZIP_DEFLATED) as z:
        for name,raw in sorted(files.items()):
            info=zipfile.ZipInfo(name,(2026,1,1,0,0,0));info.compress_type=zipfile.ZIP_DEFLATED
            info.create_system=3;info.external_attr=0o100644<<16;z.writestr(info,raw)
    digest=hashlib.sha256(output.read_bytes()).digest()
    return {'source_commit':meta['source_commit'],'sha256':digest.hex(),
        'code_sha256':base64.b64encode(digest).decode(),'execution_enabled':False,'model_calls':0}


if __name__=='__main__':
    import sys
    print(json.dumps(build(sys.argv[1]),indent=2))
