"""Committed-source bounded review ZIP; external public material requires trusted pins."""
import argparse
import base64
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import zipfile

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'src'))
from build_pilot002_runtime_package import _dependencies
from factory_runtime.pilot002_entrypoint import _read
from factory_runtime.worker import digest
from factory_runtime.review_role_lambda import load_deployment as load_role
from factory_runtime.review_controller_lambda import load_deployment as load_controller

PINNED=('factory/profiles/scope-signers.json',)


def deployment(files, *, role, material, material_digest, config, config_digest, now):
    """Validate bytes offline; hashes must originate in the privileged deployment process."""
    env={'FACTORY_BOUNDED_REVIEW_MATERIAL_DIGEST':material_digest}
    name='REVIEW_CONTROLLER.json' if role=='controller' else 'REVIEW_ROLE.json'
    key='FACTORY_BOUNDED_REVIEW_CONTROLLER_DIGEST' if role=='controller' else 'FACTORY_BOUNDED_REVIEW_ROLE_DIGEST'
    if digest(material)!=material_digest or digest(config)!=config_digest:
        raise ValueError('Deployment bytes differ from independently supplied pins')
    env[key]=config_digest;env['FACTORY_BOUNDED_REVIEW_ROLE']=role
    with tempfile.TemporaryDirectory(prefix='bounded-review-validation-') as temporary:
        root=Path(temporary)
        for path,raw in {**{p:files[p] for p in (*PINNED,'BUILD.json')},
                         'REVIEW_MATERIAL.json':material,name:config}.items():
            target=root/path;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(raw)
        (load_controller if role=='controller' else load_role)(root,env,clock=lambda:now)
    files.update({'REVIEW_MATERIAL.json':material,name:config})
    return {'material_digest':material_digest,'config_digest':config_digest,'role':role}


def build(output, *, role='controller', material=None, material_digest=None,
          config=None, config_digest=None, now=None):
    if role not in ('controller','builder','inspector','qa'):raise ValueError('Exact bounded role required')
    args=(material,material_digest,config,config_digest)
    if any(v is not None for v in args) and not all(v is not None for v in args):
        raise ValueError('Material, configuration and both independent pins are required together')
    if subprocess.check_output(['git','status','--porcelain'],cwd=ROOT,text=True).strip():
        raise RuntimeError('Package requires clean committed source')
    commit=subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip()
    output=Path(output).resolve()
    if output.is_relative_to(ROOT) or output.exists():raise RuntimeError('Use a new output outside checkout')
    def blob(name):return subprocess.check_output(['git','show',commit+':'+name],cwd=ROOT)
    paths=subprocess.check_output(['git','ls-tree','-r','--name-only',commit,'src'],cwd=ROOT,text=True).splitlines()
    files={n[4:]:blob(n) for n in paths if n.startswith('src/') and n.endswith('.py')}
    files['factory_runtime/__init__.py']=b'';files['factory_state/__init__.py']=b''
    files.update({n:blob(n) for n in PINNED})
    files['BUILD.json']=json.dumps({'source_commit':commit},sort_keys=True).encode()
    info={}
    if material is not None:
        m=Path(material).absolute();c=Path(config).absolute()
        info=deployment(files,role=role,material=_read(m.parent,m.name,196608),material_digest=material_digest,
            config=_read(c.parent,c.name,131072),config_digest=config_digest,now=now or datetime.now(timezone.utc))
    with tempfile.TemporaryDirectory(prefix='bounded-review-wheels-') as temporary:
        root=Path(temporary);lock=root/'requirements.txt'
        lock.write_bytes(blob('requirements-role-lambda.txt')+b'\n'+blob('requirements-aws-signing.txt'))
        dependencies=_dependencies(root/'wheels',lock)
        if set(dependencies)&(set(files)|{'PACKAGE.json'}):raise RuntimeError('Dependency shadows package source')
        files.update(dependencies)
    files['PACKAGE.json']=json.dumps({'source_commit':commit,
        'files':{n:hashlib.sha256(raw).hexdigest() for n,raw in sorted(files.items())}},
        sort_keys=True,separators=(',',':')).encode()
    with zipfile.ZipFile(output,'x',compression=zipfile.ZIP_DEFLATED) as archive:
        for name,raw in sorted(files.items()):
            item=zipfile.ZipInfo(name,(2026,1,1,0,0,0));item.compress_type=zipfile.ZIP_DEFLATED
            item.create_system=3;item.external_attr=0o100644<<16;archive.writestr(item,raw)
    sha=hashlib.sha256(output.read_bytes()).digest()
    return {'source_commit':commit,'sha256':sha.hex(),'code_sha256':base64.b64encode(sha).decode(),
        'zip_bytes':output.stat().st_size,'execution_enabled':False,'model_calls':0,**info}


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('output',type=Path)
    parser.add_argument('--role',choices=('controller','builder','inspector','qa'),default='controller')
    for name in ('material','material-digest','config','config-digest'):parser.add_argument('--'+name)
    print(json.dumps(build(**vars(parser.parse_args())),indent=2))
