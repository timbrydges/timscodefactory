"""Reproducible role ZIP from an exact clean checkout and hash-locked wheels."""
import base64
import hashlib
import json
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def build(output, *, extra_paths=()):
    commit = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip()
    if subprocess.check_output(['git', 'status', '--porcelain'], cwd=ROOT, text=True).strip():
        raise RuntimeError('role package requires a clean checkout')
    output = Path(output).resolve()
    if output.is_relative_to(ROOT):
        raise RuntimeError('write build outputs outside the checkout')
    with tempfile.TemporaryDirectory(prefix='factory-role-build-') as temporary:
        target = Path(temporary)
        subprocess.run([sys.executable, '-m', 'pip', 'install', '--require-hashes', '--only-binary=:all:',
            '--platform', 'manylinux_2_34_x86_64', '--platform', 'manylinux_2_28_x86_64',
            '--platform', 'manylinux2014_x86_64', '--python-version', '312', '--implementation', 'cp',
            '--abi', 'cp312', '--no-compile', '--target', str(target),
            '-r', str(ROOT/'requirements-ci.txt'), '-r', str(ROOT/'requirements-role-lambda.txt')], check=True)
        files = {str(p.relative_to(target)): p.read_bytes() for p in target.rglob('*')
                 if p.is_file() and '__pycache__' not in p.parts and p.suffix != '.pyc' and 'bin' not in p.parts}
        for p in (ROOT/'src').rglob('*.py'):
            files[str(p.relative_to(ROOT/'src'))] = p.read_bytes()
        for name in ('scope-signers.json', 'kms-signers.json'):
            path = 'factory/profiles/' + name; files[path] = (ROOT/path).read_bytes()
        for path in extra_paths:
            relative = Path(path)
            if relative.is_absolute() or '..' in relative.parts or not (ROOT / relative).is_file():
                raise RuntimeError('invalid package extra path')
            files[relative.as_posix()] = (ROOT / relative).read_bytes()
        files['BUILD.json'] = (json.dumps({'source_commit': commit}, sort_keys=True)+'\n').encode()
        output.parent.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(output, 'w', compression=zipfile.ZIP_DEFLATED) as archive:
            for name, raw in sorted(files.items()):
                info = zipfile.ZipInfo(name, (2026, 1, 1, 0, 0, 0)); info.compress_type = zipfile.ZIP_DEFLATED
                info.external_attr = 0o100644 << 16
                archive.writestr(info, raw)
    raw_digest = hashlib.sha256(output.read_bytes()).digest()
    manifest = {'source_commit': commit, 'sha256': raw_digest.hex(),
                'code_sha256': base64.b64encode(raw_digest).decode(), 'zip_bytes': output.stat().st_size}
    output.with_suffix('.json').write_text(json.dumps(manifest, indent=2)+'\n')
    print(json.dumps(manifest, indent=2))


if __name__ == '__main__':
    build(sys.argv[1])
