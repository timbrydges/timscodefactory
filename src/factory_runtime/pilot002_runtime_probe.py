"""Packaging probe only: no active dispatch branch, credentials or cloud clients."""
import hashlib
import json
import os
import re
from pathlib import Path, PurePosixPath

from factory_state.model import StateError
from .pilot002_bootstrap import facts,TASK

FLAG='FACTORY_PILOT002_EXECUTION_ENABLED'
ROLE='FACTORY_PILOT002_ROLE'


def probe(event, *, root, env):
    if env.get(FLAG)!='false' or env.get(ROLE) not in ('builder','inspector','qa'):
        raise StateError('Pilot 002 probe requires explicit disabled execution and fixed role')
    try:
        with (root/'PACKAGE.json').open('rb') as stream:raw=stream.read(262145)
        if len(raw)>262144:raise ValueError('oversized index')
        index=json.loads(raw)
        commit=index['source_commit'];files=index['files']
        if (set(index)!={'source_commit','files'} or not isinstance(commit,str) or
                not re.fullmatch('[0-9a-f]{40}',commit) or not isinstance(files,dict) or
                not 1<=len(files)<=1000 or not {'BUILD.json','factory_runtime/pilot002_adapter.py'}<=set(files) or
                not isinstance(event,dict) or set(event)!={'kind','source_commit','role'} or
                event!={'kind':'pilot002_runtime_probe','source_commit':commit,'role':env[ROLE]}):
            raise ValueError('probe context differs')
        total=0
        for name,expected in files.items():
            path=PurePosixPath(name)
            if (not name or '\\' in name or ':' in name or path.is_absolute() or '..' in path.parts or
                    str(path)!=name or not isinstance(expected,str) or not re.fullmatch('[0-9a-f]{64}',expected)):
                raise ValueError('invalid package path or digest')
            local=root.joinpath(*path.parts)
            if any(parent.is_symlink() for parent in (local,*local.parents)):
                raise ValueError('package symlink')
            with local.open('rb') as stream:content=stream.read(16777217)
            total+=len(content)
            if len(content)>16777216 or total>33554432 or hashlib.sha256(content).hexdigest()!=expected:
                raise ValueError('package content differs')
        if json.loads((root/'BUILD.json').read_bytes())!={'source_commit':commit}:
            raise ValueError('build identity differs')
        facts(root)
        # Import the actual dependency chain without constructing a client.
        from .pilot002_adapter import Pilot002Adapter
        from .pilot002_packets import builder_packet
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        import cryptography
        import botocore
        # RFC 8032 test vector 1: public verification only, no private key.
        key=bytes.fromhex('d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a')
        signature=bytes.fromhex('e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555f'
            'b8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b')
        Ed25519PublicKey.from_public_bytes(key).verify(signature,b'')
        packet=builder_packet(root)
        return {'status':'PILOT002_DISABLED_PACKAGE_VERIFIED','role':env[ROLE],'task_id':TASK,
            'source_commit':commit,'package_index_digest':'sha256:'+hashlib.sha256(raw).hexdigest(),
            'builder_packet_digest':packet['packet_digest'],'verified_files':len(files),
            'cryptography_version':cryptography.__version__,'botocore_version':botocore.__version__,
            'model_calls':0,'cloud_clients_created':0,'execution_enabled':False,'gate_authority':False}
    except Exception:
        raise StateError('Pilot 002 disabled package verification failed') from None


def handler(event, context):
    return probe(event,root=Path(os.environ.get('LAMBDA_TASK_ROOT','/var/task')),env=os.environ)
