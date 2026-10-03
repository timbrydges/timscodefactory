"""Build only the bootstrap handler and state serialization; AWS SDK comes from Lambda."""
import base64
import hashlib
import json
import subprocess
import sys
import zipfile
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'src'))
from factory_runtime.pilot002_bootstrap import PINNED, facts


def build(output):
    facts(ROOT)
    if subprocess.check_output(['git','status','--porcelain'],cwd=ROOT,text=True).strip():
        raise RuntimeError('Bootstrap package requires clean reviewed source')
    commit=subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip()
    output=Path(output).resolve()
    if output.is_relative_to(ROOT): raise RuntimeError('Build outside checkout')
    files={name:(ROOT/name).read_bytes() for name in PINNED}
    for name in ('factory_runtime/pilot002_bootstrap.py','factory_state/model.py','factory_state/dynamodb.py'):
        files[name]=(ROOT/'src'/name).read_bytes()
    files.update({'factory_runtime/__init__.py':b'','factory_state/__init__.py':b'',
                  'BUILD.json':json.dumps({'source_commit':commit}).encode()})
    with zipfile.ZipFile(output,'x',compression=zipfile.ZIP_DEFLATED) as archive:
        for name,raw in sorted(files.items()):
            info=zipfile.ZipInfo(name,(2026,1,1,0,0,0)); info.compress_type=zipfile.ZIP_DEFLATED
            info.external_attr=0o100644<<16; archive.writestr(info,raw)
    digest=hashlib.sha256(output.read_bytes()).digest()
    return {'source_commit':commit,'sha256':digest.hex(),'code_sha256':base64.b64encode(digest).decode(),
            'bytes':output.stat().st_size,'model_calls':0}


if __name__=='__main__': print(json.dumps(build(sys.argv[1]),indent=2))
