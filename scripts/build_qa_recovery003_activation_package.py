"""Offline activation packaging; never signs, uploads, grants access or enables execution."""
import argparse
import base64
import hashlib
import json
import sys
import tempfile
import zipfile
from datetime import datetime,timezone
from pathlib import Path

import build_qa_recovery003_package as inert

sys.path.insert(0,str(inert.ROOT/'src'))
from factory_runtime.qa_recovery003 import RecoveryAttemptStore,digest
from factory_runtime.qa_recovery003_authorization import BUILDER_DIGEST,REQUEST_DIGEST
from factory_runtime.qa_recovery003_entrypoint import ACTIVATION,ACTIVATION_SHA,load_activation
from factory_runtime.qa_recovery003_adapter import Pilot002Adapter
from factory_runtime.pilot002_authorization import validate_readiness,_window
from factory_runtime.qa_recovery003_protocols import request_bytes
from factory_state.model import OWNER_IDENTITY


def validate_material(files,raw,now):
    if type(raw) is not bytes or not 0<len(raw)<=131072:raise ValueError('Activation exceeds bound')
    if not isinstance(now,datetime) or now.tzinfo is None or now.utcoffset() is None:raise ValueError('Aware validation time required')
    sha=hashlib.sha256(raw).hexdigest()
    with tempfile.TemporaryDirectory(prefix='recovery001-activation-check-') as directory:
        root=Path(directory)
        for name in (*inert.MATERIAL,'BUILD.json'):
            target=root/name;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(files[name])
        (root/ACTIVATION).write_bytes(raw)
        doc,context,_keys=load_activation(root,{ACTIVATION_SHA:sha},now)
        RecoveryAttemptStore(None,root=root)
        if digest(context['builder_response'])!=BUILDER_DIGEST:raise ValueError('Builder context differs')
        request=request_bytes(root,role='qa',builder_response=context['builder_response'],candidate_commit=context['candidate_commit'])
        if digest(request)!=REQUEST_DIGEST:raise ValueError('Recovery request differs')
        adapter=Pilot002Adapter(**context,role='qa',qualification=doc['qualification'],clock=lambda:now,enabled=False)
        price=adapter.pricing
        if (price['kind']!='pilot002_google_free_tier_cost_bound' or
                type(price['maximum_cost_micro_usd']) is not int or price['maximum_cost_micro_usd']!=0 or
                not _window(price,now,300)):
            raise ValueError('QA recovery requires a fresh five-minute zero-cost bound')
        bindings={k:price[k] for k in ('role','model_id','task_id','source_commit','contract_digest','packet_digest','request_digest')}
        validate_readiness(doc['readiness'],bindings=bindings,now=now)
        if doc['readiness']['kind']!='pilot002_reviewer_first_generation_readiness':
            raise ValueError('QA first-generation readiness required')
        expires=min(price['expires_at'],doc['readiness']['expires_at'],
            *(entry['expires_at'] for entry in doc['signer_registry']['signers'] if entry['identity']==OWNER_IDENTITY))
    return {'activation_sha256':sha,'request_digest':REQUEST_DIGEST,'material_expires_at':expires,
        'maximum_cost_micro_usd':price['maximum_cost_micro_usd'],'activation_authorized':False}


def build(output,*,activation,now=None):
    output=Path(output).resolve()
    if output.is_relative_to(inert.ROOT) or output.exists():raise RuntimeError('Use a new output outside checkout')
    with Path(activation).open('rb') as stream:raw=stream.read(131073)
    if not 0<len(raw)<=131072:raise ValueError('Activation exceeds bound')
    now=now or datetime.now(timezone.utc)
    with tempfile.TemporaryDirectory(prefix='recovery001-activation-package-') as directory:
        archive=Path(directory)/'inert.zip';metadata=inert.build(archive)
        with zipfile.ZipFile(archive) as source:
            files={name:source.read(name) for name in source.namelist()}
        index=json.loads(files.pop('PACKAGE.json'))
        if (index['source_commit']!=metadata['source_commit'] or set(index['files'])!=set(files) or
                any(hashlib.sha256(files[n]).hexdigest()!=h for n,h in index['files'].items())):
            raise ValueError('Inert archive integrity differs')
        checked=validate_material(files,raw,now)
        files[ACTIVATION]=raw
        index['files']={name:hashlib.sha256(value).hexdigest() for name,value in sorted(files.items())}
        files['PACKAGE.json']=json.dumps(index,sort_keys=True,separators=(',',':')).encode()
        with zipfile.ZipFile(output,'x',compression=zipfile.ZIP_DEFLATED) as target:
            for name,value in sorted(files.items()):
                info=zipfile.ZipInfo(name,(2026,1,1,0,0,0));info.compress_type=zipfile.ZIP_DEFLATED
                info.create_system=3;info.external_attr=0o100644<<16;target.writestr(info,value)
    sha=hashlib.sha256(output.read_bytes()).digest()
    return {**metadata,**checked,'sha256':sha.hex(),'code_sha256':base64.b64encode(sha).decode(),
        'zip_bytes':output.stat().st_size,'activation_included':True}


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('output');parser.add_argument('--activation',required=True)
    args=parser.parse_args();print(json.dumps(build(args.output,activation=args.activation),indent=2))
