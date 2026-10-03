"""Synthetic-only execution of the exact inspected CLI; not an OS sandbox.

No caller paths, input bytes or commands are accepted. The controls contain the
recorded findings only for this fixed acceptance harness, not unrestricted use.
"""
import base64
import hashlib
import os
import stat
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from factory_state.model import StateError
from factory_state.scope import SignedScopeStore, canonical
from .review_preparation import prepare, validate_packet, pinned, digest, BOOTSTRAP, BOOTSTRAP_SHA
from .security_report import execute as static_report
from .qa_execution import verify_process

PROOF='factory/evidence/security-static-attestation-live-proof-2026-10-03.json'
PROOF_SHA='01868bd1a5bffc2f5032e13c9464f536af5dc83780d5c6df6260b7f3a008d34d'
SCOPE='fixed-candidate-synthetic-fixtures-only'
CONTROLS={'caller_paths_accepted':False,'caller_bytes_accepted':False,
          'private_temporary_directory':True,'regular_files_only':True,
          'child_environment':'minimal-no-provider-credentials','process_timeout_seconds':5,
          'candidate_source':'exact-reviewed-sha256','raw_output_published':False,
          'os_sandbox_claimed':False,'production_use_authorized':False}


def fixtures():
    return [('public-ascii',b'public fixture\n',True),
            ('public-unicode','public \u00e9 \U0001f642'.encode(),True),
            ('byte-boundary',b'x'*4096,True),
            ('oversized',b'x'*4097,False),('invalid-utf8',b'\xff',False)]


def evidence(root):
    expected=static_report(root)
    proof=pinned(root,PROOF,PROOF_SHA); result=proof['result']; payload=result['payload']
    boot=pinned(root,BOOTSTRAP,BOOTSTRAP_SHA)
    identity=next(x for x in boot['identities'] if x['role']=='security')
    signed=SignedScopeStore('unused',None,{identity['identity']:identity['public_key_pem'].encode()})._verify(
        payload,base64.b64decode(result['signature_base64'],validate=True),identity['identity'],
        datetime.fromtimestamp(payload['issued_at'],timezone.utc))
    if (signed!=proof['signed_payload_digest'] or canonical(result['report'])!=canonical(expected) or
            payload['report_digest']!=expected['report_digest'] or payload['finding_count']!=3 or
            payload['gate_authority'] is not False):
        raise StateError('Security static provenance differs')
    return expected,signed


def regular(path, directory):
    if path.is_symlink() or path.parent!=directory or not stat.S_ISREG(path.stat(follow_symlinks=False).st_mode):
        raise StateError('Synthetic runner requires private regular files')


def run_fixture(program, target, directory):
    regular(program,directory); regular(target,directory)
    # Python isolation is not filesystem isolation. Exact source and closed input
    # selection are mandatory; the caller cannot select a different program.
    env={'LANG':'C.UTF-8'}
    for key in ('SYSTEMROOT','WINDIR'):
        if key in os.environ: env[key]=os.environ[key]
    try:
        return subprocess.run([sys.executable,'-I','-S','-B',str(program),str(target)],
            cwd=directory,env=env,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,timeout=5,check=False,close_fds=True)
    except (subprocess.TimeoutExpired,OSError):
        raise StateError('Synthetic Security execution failed or timed out; no retry') from None


def material(root, packet):
    validate_packet(packet,root=root)
    if packet['role']!='security': raise StateError('Security packet required')
    observations,signed=evidence(root)
    return {'scope':SCOPE,'candidate_commit':packet['candidate_commit'],
        'contract_digest':packet['contract_digest'],'packet_digest':packet['packet_digest'],
        'source_sha256':packet['files_sha256']['fingerprint.py'],
        'runner_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        'static_payload_digest':signed,'findings':observations['findings'],'controls':CONTROLS,
        'limitations':['Controls apply only to the closed synthetic acceptance runner',
            'No general filesystem sandbox or unrestricted CLI safety is established',
            'Input echo remains required by the contract; only synthetic data is used here'],
        'model_calls':0,'task_state_writes':0,'gate_authority':False,'production_release_authorized':False}


def execute(root, *, packet=None):
    packet=prepare(root,role='security') if packet is None else packet
    common=material(root,packet)
    if sys.version_info[:2]!=(3,12): raise StateError('Security validation requires Python 3.12')
    source=packet['untrusted_material']['files']['fingerprint.py'].encode()
    if hashlib.sha256(source).hexdigest()!=common['source_sha256']: raise StateError('Candidate changed')
    results=[]
    with tempfile.TemporaryDirectory(prefix='factory-security-synthetic-') as temp:
        directory=Path(temp); program=directory/'fingerprint.py'; program.write_bytes(source)
        target=directory/'synthetic.bin'
        for name,data,valid in fixtures():
            with target.open('xb') as f: f.write(data)
            regular(program,directory); regular(target,directory)
            if program.read_bytes()!=source or target.read_bytes()!=data: raise StateError('Fixture changed')
            try:
                result=run_fixture(program,target,directory)
                passed=verify_process(result,data=data,valid=valid)
            except StateError:
                passed=False
            results.append({'case':name,'input_sha256':hashlib.sha256(data).hexdigest(),
                            'input_bytes':len(data),'expected_success':valid,'passed':passed})
            target.unlink()
        if program.read_bytes()!=source: raise StateError('Executable changed during validation')
    value={**common,'status':'BOUNDED_VALIDATION_PASSED' if all(x['passed'] for x in results) else 'BOUNDED_VALIDATION_FAILED',
           'cases':results,'case_count':len(results),'candidate_executions':len(results)}
    return {**value,'report_digest':digest(value)}


def validate_execution(report, packet, *, root):
    common=material(root,packet)
    if not isinstance(report,dict): raise StateError('Security report malformed')
    cases=report.get('cases')
    expected=[{'case':n,'input_sha256':hashlib.sha256(d).hexdigest(),'input_bytes':len(d),'expected_success':v}
              for n,d,v in fixtures()]
    if not isinstance(cases,list) or len(cases)!=len(expected): raise StateError('Security cases missing')
    for actual,binding in zip(cases,expected):
        if (not isinstance(actual,dict) or type(actual.get('passed')) is not bool or
                canonical({k:v for k,v in actual.items() if k!='passed'})!=canonical(binding)):
            raise StateError('Security case changed')
    passed=all(x['passed'] for x in cases)
    value={**common,'status':'BOUNDED_VALIDATION_PASSED' if passed else 'BOUNDED_VALIDATION_FAILED',
           'cases':cases,'case_count':len(expected),'candidate_executions':len(expected)}
    if canonical(report)!=canonical({**value,'report_digest':digest(value)}):
        raise StateError('Security report scope, controls or findings changed')
    return passed
