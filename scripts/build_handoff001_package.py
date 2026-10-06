"""Package committed handoff code and hash-locked SDK/verification wheels only."""
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

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'src'))
from factory_runtime.handoff001_packets import PINNED
from factory_runtime.handoff001_entrypoint import load_activation, ACTIVATION
from build_pilot002_runtime_package import _dependencies


def build(output, *, activation=None, now=None):
    if subprocess.check_output(['git', 'status', '--porcelain'], cwd=ROOT, text=True).strip():
        raise RuntimeError('Handoff package requires clean committed source')
    commit = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip()
    output = Path(output).resolve()
    if output.is_relative_to(ROOT) or output.exists():
        raise RuntimeError('Use a new package path outside the checkout')
    def blob(name): return subprocess.check_output(['git', 'show', commit+':'+name], cwd=ROOT)
    source_paths = subprocess.check_output(['git', 'ls-tree', '-r', '--name-only', commit, 'src'], cwd=ROOT, text=True).splitlines()
    files = {name[4:]: blob(name) for name in source_paths if name.startswith('src/') and name.endswith('.py')}
    # The handoff imports explicit modules only. The development convenience
    # initializers import unrelated Docker/YAML features absent from this ZIP.
    files['factory_runtime/__init__.py'] = b''
    files['factory_state/__init__.py'] = b''
    files.update({name: blob(name) for name in PINNED})
    files['BUILD.json'] = json.dumps({'source_commit': commit}, sort_keys=True).encode()
    activation_info = {}
    if activation is not None:
        with Path(activation).open('rb') as stream: raw = stream.read(262145)
        if not 0 < len(raw) <= 262144: raise ValueError('Activation size invalid')
        doc = json.loads(raw)
        env = {'FACTORY_HANDOFF001_ROLE': doc.get('role'),
            'FACTORY_HANDOFF001_ACTIVATION_SHA256': hashlib.sha256(raw).hexdigest()}
        with tempfile.TemporaryDirectory(prefix='handoff-activation-') as temporary:
            root = Path(temporary)
            for name in (*PINNED, 'BUILD.json'):
                p = root/name; p.parent.mkdir(parents=True, exist_ok=True); p.write_bytes(files[name])
            (root/ACTIVATION).write_bytes(raw)
            _, _, _, request_digest, _ = load_activation(root, env, now or datetime.now(timezone.utc))
        files[ACTIVATION] = raw
        activation_info = {'activation_sha256': env['FACTORY_HANDOFF001_ACTIVATION_SHA256'],
            'role': doc['role'], 'request_digest': request_digest, 'signed_allowance_included': True}
    with tempfile.TemporaryDirectory(prefix='handoff-dependencies-') as temporary:
        root = Path(temporary); lock = root/'requirements.txt'
        lock.write_bytes(blob('requirements-role-lambda.txt')+b'\n'+blob('requirements-aws-signing.txt'))
        files.update(_dependencies(root/'wheels', lock))
    files['PACKAGE.json'] = json.dumps({'source_commit': commit,
        'files': {name: hashlib.sha256(raw).hexdigest() for name, raw in sorted(files.items())}},
        sort_keys=True, separators=(',', ':')).encode()
    with zipfile.ZipFile(output, 'x', compression=zipfile.ZIP_DEFLATED) as archive:
        for name, raw in sorted(files.items()):
            info = zipfile.ZipInfo(name, (2026, 1, 1, 0, 0, 0)); info.compress_type = zipfile.ZIP_DEFLATED
            info.create_system = 3; info.external_attr = 0o100644 << 16
            archive.writestr(info, raw)
    digest = hashlib.sha256(output.read_bytes()).digest()
    return {'source_commit': commit, 'sha256': digest.hex(), 'code_sha256': base64.b64encode(digest).decode(),
        'zip_bytes': output.stat().st_size, 'execution_enabled': False, 'model_calls': 0, **activation_info}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('output', type=Path)
    parser.add_argument('--activation', type=Path)
    args = parser.parse_args()
    print(json.dumps(build(args.output, activation=args.activation), indent=2))
