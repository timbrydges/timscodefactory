"""Independent local checks for one hash-pinned, inspected acceptance candidate.

Not a general untrusted-code sandbox or a signed QA gate. No provider clients.
"""
import hashlib
import json
import os
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from factory_state.model import StateError
from factory_state.scope import canonical
from .review_preparation import prepare, validate_packet


def fixtures():
    """Cases authored independently of the Builder's tests."""
    return [
        ('empty', b'', True), ('nul-and-controls', b'\x00\t\r\n', True),
        ('json-escaping', b'"quote"\\slash\n', True),
        ('utf8-bom', b'\xef\xbb\xbfhello', True),
        ('combining-characters', 'e\u0301\u00e9'.encode(), True),
        ('non-bmp-boundary', ('\U0001f642'*1024).encode(), True),
        ('ascii-boundary', b'x'*4096, True),
        ('multibyte-crosses-boundary', b'x'*4095+'\u00e9'.encode(), False),
        ('ascii-over-boundary', b'x'*4097, False),
        ('invalid-continuation', b'\x80', False),
        ('overlong-utf8', b'\xc0\xaf', False),
        ('encoded-surrogate', b'\xed\xa0\x80', False),
        ('above-unicode-maximum', b'\xf4\x90\x80\x80', False),
        ('truncated-utf8', b'\xe2\x82', False),
    ]


def _run(program, arguments, directory):
    # -I isolates Python import/environment configuration, not OS permissions.
    # Only the inspected hash-pinned program is executable here.
    env = {k: v for k, v in os.environ.items()
           if k in ('SYSTEMROOT', 'WINDIR', 'TEMP', 'TMP', 'PATH', 'LANG', 'LC_ALL')}
    try:
        return subprocess.run([sys.executable, '-I', str(program), *arguments],
            cwd=directory, env=env, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5, check=False)
    except (subprocess.TimeoutExpired, OSError):
        raise StateError('independent QA execution failed or timed out') from None


def verify_process(result, *, data=None, valid=False):
    if valid:
        expected = canonical({'byte_count': len(data), 'sha256': hashlib.sha256(data).hexdigest(),
                              'text': data.decode('utf-8')}) + b'\n'
        return result.returncode == 0 and result.stdout == expected and result.stderr == b''
    return (result.returncode != 0 and result.stdout == b'' and
            result.stderr.startswith(b'error: ') and 0 < len(result.stderr) <= 200 and
            b'Traceback' not in result.stderr and result.stderr.count(b'\n') == 1)


def execute(root, *, packet=None):
    packet = prepare(root, role='qa') if packet is None else packet
    validate_packet(packet, root=root)
    if packet['role'] != 'qa' or sys.version_info[:2] != (3, 12):
        raise StateError('independent QA requires QA packet and Python 3.12')
    source = packet['untrusted_material']['files']['fingerprint.py'].encode()
    expected_hash = packet['files_sha256']['fingerprint.py']
    if hashlib.sha256(source).hexdigest() != expected_hash:
        raise StateError('independent QA executable differs')
    results = []
    with tempfile.TemporaryDirectory(prefix='factory-independent-qa-') as directory:
        directory = Path(directory)
        program = directory/'fingerprint.py'
        program.write_bytes(source)
        input_path = directory/'fixture with spaces.txt'
        for name, data, valid in fixtures():
            input_path.write_bytes(data)
            try:
                first = _run(program, [str(input_path)], directory)
                second = _run(program, [str(input_path)], directory)
                passed = (verify_process(first, data=data, valid=valid) and
                          verify_process(second, data=data, valid=valid) and
                          (first.returncode, first.stdout, first.stderr) ==
                          (second.returncode, second.stdout, second.stderr))
            except StateError:
                passed = False
            results.append({'case':name, 'passed':passed, 'input_sha256':hashlib.sha256(data).hexdigest(),
                            'input_bytes':len(data), 'expected_success':valid})
        for name, arguments in [('no-argument', []), ('extra-argument', ['one','two']),
                               ('missing-file', [str(directory/'absent')]),
                               ('directory-input', [str(directory)])]:
            try:
                passed = verify_process(_run(program, arguments, directory))
            except StateError:
                passed = False
            results.append({'case':name, 'passed':passed, 'expected_success':False})
        if hashlib.sha256(program.read_bytes()).hexdigest() != expected_hash:
            raise StateError('independent QA source changed during execution')
    report = {'status':'LOCAL_QA_PASSED_UNSIGNED' if all(r['passed'] for r in results)
              else 'LOCAL_QA_FAILED_UNSIGNED', 'candidate_commit':packet['candidate_commit'],
        'contract_digest':packet['contract_digest'], 'packet_digest':packet['packet_digest'],
        'executed_source_sha256':expected_hash,
        'runner_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        'runtime':sys.version, 'platform':sys.platform,
        'observed_at':datetime.now(timezone.utc).isoformat(), 'cases':results,
        'case_count':len(results), 'model_calls':0, 'gate_authority':False,
        'production_release_authorized':False,
        'limitations':['Local inspected-code execution, not an OS sandbox',
                       'Does not establish a QA lease, signature or controller acceptance',
                       'Does not replace the required Builder test command']}
    return {**report, 'report_digest':'sha256:'+hashlib.sha256(canonical(report)).hexdigest()}
