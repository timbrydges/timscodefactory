"""Verify the actual Python 3.12 Lambda ZIP without host site-packages or AWS IO."""
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys
import tempfile
import zipfile


def verify(package):
    if sys.version_info[:2] != (3, 12): raise RuntimeError('Use the target Python 3.12 runtime')
    with tempfile.TemporaryDirectory(prefix='handoff-package-proof-') as temporary:
        root = Path(temporary)
        with zipfile.ZipFile(package) as archive:
            entries = archive.infolist(); names = [item.filename for item in entries]
            if (len(entries) > 10000 or len(names) != len(set(names)) or
                    sum(item.file_size for item in entries) > 268435456 or
                    any(PurePosixPath(name).is_absolute() or '..' in PurePosixPath(name).parts or
                        '\\' in name or ':' in name or '.env' in PurePosixPath(name).parts or
                        any(part.startswith('.env.') for part in PurePosixPath(name).parts) for name in names) or
                    any((item.external_attr >> 16) & 0o170000 == 0o120000 for item in entries)):
                raise RuntimeError('Unsafe or oversized package archive')
            archive.extractall(root)
        index = json.loads((root/'PACKAGE.json').read_bytes())
        if (set(index) != {'source_commit', 'files'} or not re.fullmatch('[0-9a-f]{40}', index['source_commit']) or
                set(names) != set(index['files']) | {'PACKAGE.json'} or
                any(hashlib.sha256((root/name).read_bytes()).hexdigest() != digest for name, digest in index['files'].items()) or
                json.loads((root/'BUILD.json').read_bytes()) != {'source_commit': index['source_commit']}):
            raise RuntimeError('Package index or committed source differs')
        code = '''import sys
from pathlib import Path
sys.path.insert(0, sys.argv[1])
from factory_runtime.handoff001_entrypoint import dispatch
from factory_state.model import StateError
from botocore.session import get_session
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
assert 'ED25519_SHA_512' in get_session().get_service_model('kms').shape_for('SigningAlgorithmSpec').enum
key = Ed25519PrivateKey.generate()
key.public_key().verify(key.sign(b'synthetic-package-proof'), b'synthetic-package-proof')
try:
    dispatch(None, None, root=Path('/does-not-exist'), env={}, clock=lambda: None)
except StateError as error:
    assert str(error) == 'Handoff entry point disabled'
else:
    raise AssertionError('Disabled boundary did not reject')
print('ISOLATED_PYTHON312_PACKAGE_VERIFIED_NO_AWS_OR_MODEL_CALLS')
'''
        subprocess.run([sys.executable, '-I', '-S', '-c', code, str(root)], check=True, timeout=30)
    return {'status': 'ISOLATED_PACKAGE_VERIFIED', 'source_commit': index['source_commit'], 'model_calls': 0}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__); parser.add_argument('package', type=Path)
    print(json.dumps(verify(parser.parse_args().package)))
