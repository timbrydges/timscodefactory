"""Audit saved three-provider evidence at its historical verification time."""
import base64
from datetime import datetime
import hashlib
import json
from pathlib import Path
import re
import sys
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'src'))
from factory_runtime.handoff004_packets import facts,parse_builder,TASK
from factory_runtime.handoff004_protocols import request_bytes
from factory_runtime.handoff004_receipts import verify_chain,sha
from factory_state.scope import canonical
from factory_state.signers import validate_trusted_signers
SOURCE='1b2819985098e63acf1d29ad2c31fca46a0a9231'
CANDIDATE='994719a384b7ac96abeb67e4b2addcab2deb4763'

def verify(folder,root=ROOT):
    def read(name):
        raw=(folder/(name+'.json')).read_bytes()
        if len(raw)>131072:raise ValueError('Evidence exceeds bound')
        return json.loads(raw)
    saved=read('chain-verification')
    if saved['source_commit']!=SOURCE or saved['candidate_commit']!=CANDIDATE:
        raise ValueError('Historical binding differs')
    when=datetime.fromisoformat(saved['verified_at'])
    registry=(folder/'signer-registry.json').read_bytes()
    if hashlib.sha256(registry).hexdigest()!='663e988be61c463d16232d1d6d65e2580d06ecb5e3cac5126f72037aaa9d97e4':
        raise ValueError('Registry differs')
    keys=validate_trusted_signers(json.loads(registry),now=when)
    roles=('builder','inspector','qa')
    envelopes={r:read(r+'-live-result') for r in roles}
    builder=base64.b64decode(envelopes['builder']['output_base64'],validate=True)
    parsed=parse_builder(builder,root=root)
    requests={r:sha(request_bytes(root,role=r,**({} if r=='builder' else
        {'builder_response':builder,'candidate_commit':CANDIDATE}))) for r in roles}
    proof_raw=(folder/'candidate-python312-proof.json').read_bytes()
    proof=json.loads(proof_raw)
    def tests(commit,digest):
        return (commit==CANDIDATE and digest==parsed['candidate_digest'] and
            sha(proof_raw)==saved['test_proof_digest'] and parsed['files']==facts(root)[1]['files'] and
            proof['source_commit']==SOURCE and proof['candidate_commit']==CANDIDATE and
            proof['runtime']=='python3.12-linux' and proof['python_version'].startswith('3.12.') and
            proof['credentials_in_environment'] is False and proof['exit_code']==0 and
            re.search(r'Ran 17 tests in [0-9.]+s\n\nOK\n$',proof['stderr']) is not None and
            'skipped' not in proof['stderr'].lower() and
            proof['files']=={n:hashlib.sha256(t.encode()).hexdigest() for n,t in parsed['files'].items()})
    result=verify_chain(envelopes,root=root,trusted_keys=keys,source_commit=SOURCE,
        candidate_commit=CANDIDATE,request_digests=requests,now=when,verify_executed_tests=tests)
    if any(saved.get(k)!=v for k,v in result.items()):raise ValueError('Saved chain report differs')
    for role in roles:
        row=read(role+'-attempt-observation');claim=read(role+'-controller-observation')
        journal=read(role+'-dispatch-journal')
        if ([entry['stage'] for entry in journal]!=['PREPARATION_STARTED',
                'DISPATCH_INVOKE_STARTED_NO_RETRY','DISPATCH_INVOKE_RETURNED','RESTORE_FINISHED'] or
                journal[0]['source_commit']!=SOURCE or journal[0]['role']!=role or
                journal[2]['function_error'] is not None or journal[3]['errors']!=[]):
            raise ValueError('Single invocation or restoration journal differs')
        raw=canonical(envelopes[role]);cost=envelopes[role]['payload']['actual_micro_usd']
        if (row['PK']['S']!='HANDOFF#004#TASK#'+TASK+'#ROLE#'+role or row['role']['S']!=role or
                row['source_commit']['S']!=SOURCE or row['request_digest']['S']!=requests[role] or
                row['reservation_status']['S']!='HELD' or row['reserved_micro_usd']['N']!='250000' or
                row['status']['S']!='COMPLETE' or claim['status']['S']!='COMPLETE' or
                claim['PK']['S']!='HANDOFF#004#CONTROLLER#'+TASK+'#'+role or
                claim['request_digest']['S']!=requests[role] or
                row['output_digest']['S']!=sha(raw) or int(row['actual_micro_usd']['N'])!=cost or
                claim['output_digest']['S']!=sha(raw) or claim['signed_receipt']['S'].encode()!=raw):
            raise ValueError('Permanent claim or signed result differs')
    completion=read('completion-recovery-result')
    if (completion['status']!='COMPLETED_NO_DISPATCH' or completion['worker_invocations']!=0 or
            completion['gate_authority'] is not False or completion['execution_authorized'] is not False or
            completion['receipt_digests']!=result['receipt_digests'] or
            completion['reported_actual_micro_usd']!=result['reported_actual_micro_usd']):
        raise ValueError('Read-only completion differs')
    before=read('prior-observation');after=read('final-observation')
    expected_task={'status':'OBSERVED','state':'PAUSED','version':0,'active_leases':0}
    if (after['status']!='OBSERVED' or after['task']!=before['task'] or after['task']!=expected_task or
            len(after['workers'])!=24 or len(after['attempts'])!=21 or
            after['dispatcher_worker_invoke_permissions']!=0 or
            after['gate_authority'] is not False or after['execution_authorized'] is not False or
            {k:after['attempts'][k] for k in before['attempts']}!=before['attempts']):
        raise ValueError('Final observation or preserved history differs')
    for row in after['workers'].values():
        if row!={'status':'OBSERVED','execution_flag':False,'reserved_concurrency':0,'disabled_observed':True}:
            raise ValueError('A worker was not observed disabled')
    if (set(after['workers'])!=set(before['workers'])|{'handoff004_'+r for r in (*roles,'dispatcher')} or
            set(after['attempts'])!=set(before['attempts'])|{'handoff004_'+r for r in roles}):
        raise ValueError('Fixed observation inventory differs')
    for role in roles:
        if after['attempts']['handoff004_'+role]!={'status':'COMPLETE','reservation_status':'HELD',
                'reserved_micro_usd':250000,'reported_actual_micro_usd':envelopes[role]['payload']['actual_micro_usd'],
                'attempt_reusable':False}:raise ValueError('Final attempt observation differs')
    return {'status':'HISTORICAL_COMPLETE_HANDOFF_VERIFIED_NOT_AUTHORIZATION',
        'reported_completed_micro_usd':result['reported_actual_micro_usd'],'independent_tests':17,
        'execution_authorized':False,'gate_authority':False,'invoice_verified':False,
        'limitation':'Signatures verified historically; database, tests and disabled states are operator observations.'}

if __name__=='__main__':print(json.dumps(verify(ROOT/'factory/evidence/handoff-004-live'),indent=2))
