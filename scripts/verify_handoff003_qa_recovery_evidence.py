"""Historical failed recovery audit; never live authority or permission to retry."""
import base64,hashlib,json,sys
from datetime import datetime
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT),str(ROOT/'src')]
from factory_state.model import OWNER_IDENTITY
from factory_state.scope import SignedScopeStore,canonical
from factory_state.signers import validate_trusted_signers
from factory_runtime.handoff003_qa_recovery_authorization import draft,TASK,PK,SCOPE_DIGEST

SOURCE='0b460df22c4abc02a038be0f0a8345c1779eb58b'
ACTIVATION_SHA='2d3989688d2f04942208b2b19c3acf7403cf25a54172505ae696cdacfb6cf313'

def verify(folder,root=ROOT):
    def read(name):
        raw=(folder/(name+'.json')).read_bytes()
        if len(raw)>131072:raise ValueError('Evidence too large')
        return json.loads(raw)
    raw=(folder/'owner-activation.json').read_bytes()
    if hashlib.sha256(raw).hexdigest()!=ACTIVATION_SHA:raise ValueError('Historical owner activation differs')
    doc=json.loads(raw);when=datetime.fromisoformat('2026-10-06T05:33:52.628578+00:00')
    keys=validate_trusted_signers(doc['signer_registry'],now=when);payload=doc['allowance']['payload']
    expected=draft(root=root,source_commit=SOURCE,qualification=doc['qualification'],readiness=doc['readiness'],now=when,
        issued_at=payload['issued_at'],expires_at=payload['expires_at'])
    if canonical(payload)!=canonical(expected):raise ValueError('Historical scope differs')
    SignedScopeStore('unused',None,keys)._verify(payload,base64.b64decode(doc['allowance']['signature'],validate=True),OWNER_IDENTITY,when)
    result=read('live-result')
    if result!={'status':'QA_RECOVERY_FAILED_NO_RETRY','failure_stage':'provider','failure_code':'http_status_503',
        'attempt_reusable':False,'hold_release_authorized':False,'gate_authority':False}:raise ValueError('Provider failure evidence differs')
    row=read('attempt-observation')
    for field,value in {'PK':PK,'task_id':TASK,'source_commit':SOURCE,'contract_digest':SCOPE_DIGEST,'status':'STARTED',
        'reservation_status':'HELD','request_digest':payload['request_digest'],'approval_digest':'sha256:'+hashlib.sha256(canonical(payload)).hexdigest()}.items():
        if row.get(field)!={'S':value}:raise ValueError('Permanent recovery claim differs')
    if row.get('reserved_micro_usd')!={'N':'250000'} or 'actual_micro_usd' in row or 'output_digest' in row:raise ValueError('Unknown cost or hold differs')
    journal=read('live-journal')
    if [v['stage'] for v in journal]!=['PREPARATION_STARTED','LIVE_INVOKE_STARTED_NO_RETRY','LIVE_INVOKE_RETURNED','RESTORED_DISABLED']:
        raise ValueError('One-call journal differs')
    if journal[1]['activation_sha256']!=ACTIVATION_SHA or journal[-1]['reserved_concurrency']!=0:raise ValueError('Activation or shutdown differs')
    status=read('final-status')
    if (status['status']!='OBSERVED' or len(status['workers'])!=19 or not status['all_workers_disabled_observed'] or
        any(v.get('disabled_observed') is not True or v.get('reserved_concurrency')!=0 for v in status['workers'].values()) or
        status['task']!={'status':'OBSERVED','state':'PAUSED','version':0,'active_leases':0}):raise ValueError('Disabled observation differs')
    for name in ('handoff003_qa','handoff003_qa_recovery001'):
        if status['attempts'][name]!={'status':'STARTED','reservation_status':'HELD','reserved_micro_usd':250000,
            'reported_actual_micro_usd':None,'attempt_reusable':False}:raise ValueError('Prior or recovery hold differs')
    return {'status':'HISTORICAL_RECOVERY_503_VERIFIED_NOT_AUTHORIZATION','model_attempts':1,'actual_cost_known':False,
        'two_qa_holds_micro_usd':500000,'attempt_reusable':False,'execution_authorized':False,'gate_authority':False}

if __name__=='__main__':print(json.dumps(verify(ROOT/'factory/evidence/handoff-003-qa-recovery-001-live')))
