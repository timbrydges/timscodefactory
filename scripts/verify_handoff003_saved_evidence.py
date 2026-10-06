"""Audit completed signatures and an uncertain QA observation, never authority."""
import base64
from datetime import datetime
import hashlib
import json
from pathlib import Path
import re
import sys
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'src'))
from factory_runtime.handoff003_packets import facts,parse_builder,TASK
from factory_runtime.handoff003_protocols import request_bytes
from factory_runtime.handoff003_receipts import verify_predecessors,sha
from factory_state.scope import canonical
from factory_state.signers import validate_trusted_signers
SOURCE='059f42ae087b0c6429e71e0cb5e0a24f978eed88'
CANDIDATE='994719a384b7ac96abeb67e4b2addcab2deb4763'

def verify(folder,root=ROOT):
    def read(name):
        raw=(folder/(name+'.json')).read_bytes()
        if len(raw)>131072:raise ValueError('Evidence exceeds bound')
        return json.loads(raw)
    saved=read('partial-verification')
    if saved['source_commit']!=SOURCE or saved['candidate_commit']!=CANDIDATE:raise ValueError('Historical binding differs')
    when=datetime.fromisoformat(saved['verified_at'])
    registry=(folder/'signer-registry.json').read_bytes()
    if hashlib.sha256(registry).hexdigest()!='663e988be61c463d16232d1d6d65e2580d06ecb5e3cac5126f72037aaa9d97e4':raise ValueError('Registry differs')
    keys=validate_trusted_signers(json.loads(registry),now=when)
    envelopes={r:read(r+'-live-result') for r in ('builder','inspector')}
    builder=base64.b64decode(envelopes['builder']['output_base64'],validate=True)
    parsed=parse_builder(builder,root=root)
    requests={r:sha(request_bytes(root,role=r,**({} if r=='builder' else {'builder_response':builder,'candidate_commit':CANDIDATE}))) for r in ('builder','inspector','qa')}
    verify_predecessors(envelopes,next_role='qa',root=root,trusted_keys=keys,source_commit=SOURCE,
        candidate_commit=CANDIDATE,request_digests={r:requests[r] for r in envelopes},now=when)
    total=0
    for role in ('builder','inspector','qa'):
        row=read(role+'-attempt-observation');claim=read(role+'-controller-observation')
        expected='STARTED' if role=='qa' else 'COMPLETE'
        if (row['PK']['S']!='HANDOFF#003#TASK#'+TASK+'#ROLE#'+role or row['role']['S']!=role or
                row['source_commit']['S']!=SOURCE or row['request_digest']['S']!=requests[role] or
                row['reservation_status']['S']!='HELD' or row['reserved_micro_usd']['N']!='250000' or
                row['status']['S']!=expected or claim['status']['S']!=expected or
                claim['PK']['S']!='HANDOFF#003#CONTROLLER#'+TASK+'#'+role or claim['request_digest']['S']!=requests[role]):
            raise ValueError('Permanent claim or hold differs')
        if role!='qa':
            raw=canonical(envelopes[role]);cost=envelopes[role]['payload']['actual_micro_usd']
            if (row['output_digest']['S']!=sha(raw) or int(row['actual_micro_usd']['N'])!=cost or
                    claim['output_digest']['S']!=sha(raw) or claim['signed_receipt']['S'].encode()!=raw):
                raise ValueError('Durable result differs from signed receipt')
            total+=cost
        elif 'actual_micro_usd' in row or 'signed_receipt' in claim:raise ValueError('Unknown QA outcome represented as complete')
    raw=(folder/'candidate-python312-proof.json').read_bytes();proof=json.loads(raw)
    if (sha(raw)!=saved['test_proof_digest'] or parsed['files']!=facts(root)[1]['files'] or
            proof['source_commit']!=SOURCE or proof['candidate_commit']!=CANDIDATE or
            proof['runtime']!='python3.12-linux' or not proof['python_version'].startswith('3.12.') or
            proof['credentials_in_environment'] is not False or proof['exit_code']!=0 or
            not re.search(r'Ran 17 tests in [0-9.]+s\n\nOK\n$',proof['stderr']) or
            proof['files']!={n:hashlib.sha256(t.encode()).hexdigest() for n,t in parsed['files'].items()}):
        raise ValueError('Independent test observation differs')
    stopped=read('stopped-recovery-result')
    uncertain=read('qa-dispatcher-result')
    if uncertain['status']!='DISPATCH_OUTCOME_UNCERTAIN_NO_RETRY' or uncertain['worker_invocations']!=1:
        raise ValueError('Uncertain dispatch observation differs')
    if (stopped['status']!='STOPPED_NO_RETRY' or stopped['worker_invocations']!=0 or
            stopped['execution_authorized'] is not False or saved['qa_actual_cost_known'] is not False or
            saved['reported_completed_micro_usd']!=total or saved['qa_held_micro_usd']!=250000):
        raise ValueError('Stopped result or uncertain cost differs')
    disabled=read('final-disabled')['workers']
    if set(disabled)!={'builder','inspector','qa','dispatcher'}:raise ValueError('Incomplete disabled observation')
    for role,row in disabled.items():
        flag='FACTORY_HANDOFF003_DISPATCH_ENABLED' if role=='dispatcher' else 'FACTORY_HANDOFF003_ENABLED'
        if row['reserved_concurrency']!=0 or row['environment'].get(flag)!='false':raise ValueError('Disabled observation differs')
    return {'status':'HISTORICAL_PARTIAL_HANDOFF_VERIFIED_NOT_AUTHORIZATION',
        'reported_completed_micro_usd':total,'qa_actual_cost_known':False,'qa_held_micro_usd':250000,
        'execution_authorized':False,'gate_authority':False,'invoice_verified':False,
        'limitation':'Signed completed results; database, test and disabled states are saved operator observations.'}

if __name__=='__main__':print(json.dumps(verify(ROOT/'factory/evidence/handoff-003-live'),indent=2))
