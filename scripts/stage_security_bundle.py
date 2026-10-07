"""Validate public deployment bundle bytes offline; never publish or enable them."""
from pathlib import Path
import tempfile

from factory_state.model import StateError, COMMIT_SHA
from factory_state.scope import canonical
from factory_runtime.security_deployment import load_deployment, signer_loader
from factory_runtime.security_role_lambda import load_allowance
from factory_runtime.security_provider_scope import verify
from factory_runtime.security_controller_config import load_controller_config
from factory_runtime.worker import digest

FILES={
    'REVIEW_MATERIAL.json':('FACTORY_SECURITY_MATERIAL_DIGEST',196608),
    'SECURITY_QA.json':('FACTORY_SECURITY_QA_DIGEST',8192),
    'SECURITY_SIGNERS.json':('FACTORY_SECURITY_SIGNERS_DIGEST',65536),
    'SECURITY_QA_SIGNERS.json':('FACTORY_SECURITY_QA_SIGNERS_DIGEST',65536),
    'SECURITY_ALLOWANCE.json':('FACTORY_SECURITY_ALLOWANCE_DIGEST',131072),
}
CONTROLLER=('FACTORY_SECURITY_CONTROLLER_DIGEST',16384)


def stage(files, pins, *, source_commit, role, now):
    """Pins come from an authenticated deployer, not hashes of arbitrary uploads.

    Historical QA signature/consumption, cloud custody and current claims are
    deliberately not certified by this offline check; runtime must verify them.
    """
    if (role not in ('security','controller') or type(source_commit) is not str or
            not COMMIT_SHA.fullmatch(source_commit)):
        raise StateError('Exact committed security package target required')
    required={**FILES,**({'SECURITY_CONTROLLER.json':CONTROLLER} if role=='controller' else {})}
    if type(files) is not dict or type(pins) is not dict or set(files)!=set(required) or set(pins)!=set(required):
        raise StateError('Exact public security files and independent pins required')
    env={}
    for name,(key,limit) in required.items():
        raw=files[name]
        if type(raw) is not bytes or not 0<len(raw)<=limit or digest(raw)!=pins[name]:
            raise StateError('Security bundle bytes differ from independent deployment pin')
        env[key]=pins[name]
    with tempfile.TemporaryDirectory(prefix='security-bundle-validation-') as tmp:
        root=Path(tmp)
        (root/'BUILD.json').write_bytes(canonical({'source_commit':source_commit}))
        for name,raw in files.items():(root/name).write_bytes(raw)
        deployment=load_deployment(root,env,clock=lambda:now)
        keys=signer_loader(root,env)
        signer_loader(root,env,historical=True)  # Snapshot pin only; issuance-time verification stays runtime-owned.
        doc=load_allowance(root,env,material=deployment.material,keys=keys,now=now)
        grant=verify(doc['allowance'],scope=deployment.material.prepared().scope,
            pricing=doc['pricing'],readiness=doc['readiness'],trusted_keys=keys(now),now=now)
        if role=='controller':load_controller_config(root,env,deployment=deployment,grant=grant,now=now)
    env['FACTORY_SECURITY_ENABLED']='false'
    env['FACTORY_SECURITY_CONTROLLER_ENABLED']='false'
    return dict(files),env
