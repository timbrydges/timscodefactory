"""Reverify saved handoff signatures at their recorded audit time; never live authority."""
import base64
from datetime import datetime
import hashlib
import json
from pathlib import Path
import re
import sys
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'src'))
from factory_runtime.handoff002_packets import parse_builder, facts
from factory_runtime.handoff002_protocols import request_bytes
from factory_runtime.handoff002_receipts import verify_chain,sha
from factory_state.scope import canonical
from factory_state.signers import validate_trusted_signers

SOURCE='29098df20e95cecda4ce044b4b4cf58b417ec0bb'
CANDIDATE='994719a384b7ac96abeb67e4b2addcab2deb4763'

def verify(folder,root=ROOT):
    def read(name):
        raw=(folder/(name+'.json')).read_bytes()
        if len(raw)>131072:raise ValueError('Evidence exceeds bound')
        return json.loads(raw)
    saved=read('chain-verification')
    if saved['source_commit']!=SOURCE or saved['candidate_commit']!=CANDIDATE:
        raise ValueError('Historical source or candidate differs')
    when=datetime.fromisoformat(saved['verified_at'])
    registry_raw=(folder/'signer-registry.json').read_bytes()
    if hashlib.sha256(registry_raw).hexdigest()!='663e988be61c463d16232d1d6d65e2580d06ecb5e3cac5126f72037aaa9d97e4':
        raise ValueError('Pinned historical signer registry differs')
    registry=json.loads(registry_raw)
    keys=validate_trusted_signers(registry,now=when)
    envelopes={r:read(r+'-live-result') for r in ('builder','inspector','qa')}
    builder=base64.b64decode(envelopes['builder']['output_base64'],validate=True)
    parsed=parse_builder(builder,root=root)
    requests={r:sha(request_bytes(root,role=r,**({} if r=='builder' else {'builder_response':builder,'candidate_commit':CANDIDATE}))) for r in envelopes}
    raw=(folder/'candidate-python312-proof.json').read_bytes();proof=json.loads(raw)
    def tests(commit,digest):
        if (commit!=CANDIDATE or digest!=parsed['candidate_digest'] or
                parsed['files']!=facts(root)[1]['files'] or proof['source_commit']!=SOURCE or
                proof['candidate_commit']!=commit or proof['runtime']!='python3.12-linux' or
                not proof['python_version'].startswith('3.12.') or proof['exit_code']!=0 or
                proof['credentials_in_environment'] is not False or
                not re.search(r'Ran 17 tests in [0-9.]+s\n\nOK\n$',proof['stderr']) or
                'skipped' in proof['stderr'].lower() or saved['test_proof_digest']!=sha(raw)):
            return False
        return proof['files']=={n:hashlib.sha256(t.encode()).hexdigest() for n,t in parsed['files'].items()}
    result=verify_chain(envelopes,root=root,trusted_keys=keys,source_commit=SOURCE,candidate_commit=CANDIDATE,
        request_digests=requests,now=when,verify_executed_tests=tests)
    for k,v in result.items():
        if saved.get(k)!=v:raise ValueError('Saved verification differs from signed evidence')
    for role,envelope in envelopes.items():
        row=read(role+'-attempt-observation')
        if (row['status']['S']!='COMPLETE' or row['reservation_status']['S']!='HELD' or
                row['source_commit']['S']!=SOURCE or row['request_digest']['S']!=requests[role] or
                row['output_digest']['S']!=sha(canonical(envelope)) or
                int(row['reserved_micro_usd']['N'])!=250000 or
                int(row['actual_micro_usd']['N'])!=envelope['payload']['actual_micro_usd']):
            raise ValueError('Saved attempt differs from signed result')
    return {'status':'HISTORICAL_HANDOFF_VERIFIED_NOT_AUTHORIZATION',
        'verified_at':saved['verified_at'],'reported_micro_usd':result['reported_actual_micro_usd'],
        'gate_authority':False,'execution_authorized':False,'invoice_verified':False,
        'test_evidence':'Saved operator observation; tests are not rerun by this audit'}

if __name__=='__main__':
    print(json.dumps(verify(ROOT/'factory/evidence/handoff-002-live'),indent=2))
