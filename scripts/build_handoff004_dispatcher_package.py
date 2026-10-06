"""Package a reviewed stage activation and exact immutable worker deployment pin."""
import base64
import hashlib
import json
from pathlib import Path
import tempfile
import zipfile
from build_handoff004_package import build as runtime,ROOT
from factory_runtime.handoff004_dispatcher import CONFIG
from factory_state.scope import canonical


def build(output,*,activation,config):
    output=Path(output).resolve()
    if output.exists() or output.is_relative_to(ROOT):raise ValueError('New external output required')
    doc=json.loads(Path(config).read_bytes());raw=canonical(doc)
    if len(raw)>262144 or set(doc)!={'source_commit','pin','candidate_commit','test_proof'}:
        raise ValueError('Exact bounded dispatch configuration required')
    with tempfile.TemporaryDirectory() as temporary:
        package=Path(temporary)/'runtime.zip';meta=runtime(package,activation=activation)
        if (doc['source_commit']!=meta['source_commit'] or doc['pin']['source_commit']!=meta['source_commit'] or
                doc['pin']['activation_sha256']!=meta['activation_sha256'] or doc['pin']['role']!=meta['role']):
            raise ValueError('Dispatch source, role or activation differs')
        with zipfile.ZipFile(package) as z:files={n:z.read(n) for n in z.namelist() if n!='PACKAGE.json'}
    files[CONFIG]=raw
    files['PACKAGE.json']=canonical({'source_commit':meta['source_commit'],
        'files':{n:hashlib.sha256(b).hexdigest() for n,b in sorted(files.items())}})
    with zipfile.ZipFile(output,'x',compression=zipfile.ZIP_DEFLATED) as z:
        for name,value in sorted(files.items()):
            info=zipfile.ZipInfo(name,(2026,1,1,0,0,0));info.compress_type=zipfile.ZIP_DEFLATED
            info.create_system=3;info.external_attr=0o100644<<16;z.writestr(info,value)
    digest=hashlib.sha256(output.read_bytes()).digest()
    return {'source_commit':meta['source_commit'],'sha256':digest.hex(),
        'code_sha256':base64.b64encode(digest).decode(),'dispatch_sha256':hashlib.sha256(raw).hexdigest(),
        'role':meta['role'],'execution_enabled':False,'model_calls':0}


if __name__=='__main__':
    import argparse
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('output');p.add_argument('--activation',required=True)
    p.add_argument('--config',required=True);a=p.parse_args()
    print(json.dumps(build(a.output,activation=a.activation,config=a.config),indent=2))
