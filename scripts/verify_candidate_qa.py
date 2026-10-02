"""Offline supplemental QA for the exact reviewed candidate, not gate authority."""
import ast
import hashlib
import json
import os
import random
import subprocess
import sys
import tempfile
from pathlib import Path

from factory_runtime.implementation_inspector import CANDIDATE, PACKET, PACKET_SHA, FILES, rerun_tests
from factory_state.model import StateError


def verify(root):
    raw = (root / PACKET).read_bytes()
    if hashlib.sha256(raw).hexdigest() != PACKET_SHA:
        raise StateError('candidate packet drifted')
    files = json.loads(raw)['untrusted_candidate_files']
    if set(files) != set(FILES) or any(hashlib.sha256(files[k].encode()).hexdigest() != v for k, v in FILES.items()):
        raise StateError('candidate source drifted')
    required = rerun_tests(files)
    valid = [b'', b'\x00\t\r\n', b'"\\/', b'a'*4095, b'a'*4096,
             ('\U0001f642'*1024).encode(), '\ufeffhello'.encode(), '\u2028\u2029'.encode(),
             'e\u0301\u00e9'.encode()]
    rng = random.Random(289)
    alphabet = ['a', '\x00', '\n', '"', '\\', '\u00e9', '\u4e2d', '\U0001f642']
    valid.extend(''.join(rng.choice(alphabet) for _ in range(rng.randrange(1, 80))).encode() for _ in range(32))
    invalid = [b'a'*4097, ('\U0001f642'*1024+'a').encode(), b'\xc0\x80', b'\xed\xa0\x80',
               b'\xf4\x90\x80\x80', b'\x80', b'\xe2\x82', b'\xff', b'a'*4095+b'\xc3']
    environment = {'PATH': os.defpath, 'LANG': 'C.UTF-8'}
    for key in ('SYSTEMROOT', 'WINDIR'):
        if key in os.environ: environment[key] = os.environ[key]
    with tempfile.TemporaryDirectory(prefix='factory-qa-') as directory:
        path = Path(directory)
        program = path / 'fingerprint.py'
        program.write_bytes(files['fingerprint.py'].encode())
        target = path / 'input.bin'
        def run():
            return subprocess.run([sys.executable, '-I', '-S', '-B', str(program), str(target)],
                cwd=path, env=environment, stdin=subprocess.DEVNULL,
                capture_output=True, timeout=5, check=False)
        for data in valid:
            target.write_bytes(data)
            expected = (json.dumps({'byte_count': len(data), 'sha256': hashlib.sha256(data).hexdigest(),
                'text': data.decode('utf-8')}, ensure_ascii=False, sort_keys=True, separators=(',', ':'))+'\n').encode()
            for _ in range(2):
                result = run()
                if (result.returncode, result.stdout, result.stderr) != (0, expected, b''):
                    raise StateError('supplemental canonical-output or repeatability check failed')
        for data in invalid:
            target.write_bytes(data)
            result = run()
            if result.returncode == 0 or result.stdout or not result.stderr.startswith(b'error:'):
                raise StateError('supplemental rejection check failed')
    tree = ast.parse(files['fingerprint.py'])
    imports = sorted({n.name for item in ast.walk(tree) if isinstance(item, ast.Import) for n in item.names})
    if imports != ['hashlib', 'json', 'sys']:
        raise StateError('candidate import surface changed')
    forbidden = {'eval', 'exec', '__import__', 'compile'}
    if any(isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id in forbidden for n in ast.walk(tree)):
        raise StateError('dynamic execution found')
    return {'status': 'OFFLINE_QA_PASSED_NOT_A_SIGNED_GATE_VERDICT', 'candidate_commit': CANDIDATE,
        'files_sha256': FILES, 'required_tests_passed': required['tests_passed'],
        'valid_cases': len(valid), 'invalid_cases': len(invalid),
        'supplemental_process_runs': len(valid)*2+len(invalid), 'model_calls': 0,
        'static_review': {'imports': imports, 'dynamic_execution_calls': 0,
            'limitations': 'Fixed-candidate inspection only; not a sandbox, filesystem access policy, or independent signed security verdict.'},
        'state_writes': 0, 'production_release_authorized': False}


if __name__ == '__main__':
    print(json.dumps(verify(Path(__file__).resolve().parents[1]), indent=2))
