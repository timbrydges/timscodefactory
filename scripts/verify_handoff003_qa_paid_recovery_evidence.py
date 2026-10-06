"""Audit saved paid QA acceptance; historical evidence grants no live authority."""
import base64,hashlib,json,sys
from datetime import datetime
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT),str(ROOT/'src'),str(ROOT/'scripts')]
from factory_state.scope import SignedScopeStore,canonical
from factory_runtime.handoff003_qa_paid_recovery_authorization import TASK,PK,SCOPE_DIGEST
from factory_runtime.handoff003_packets import parse_review
from factory_runtime.handoff003_receipts import IDENTITIES
from sign_handoff003_qa_paid_recovery_allowance import material

SOURCE='ccfd8860b2a665a295cd66db4ecdfb45ea36e97f'
ACTIVATION_SHA='d384a18f0c64149d834344958b34bc075485bd88437586b04c6e930683c00635'
FOLDER='factory/evidence/handoff-003-qa-recovery-002-live'

def sha(raw):return 'sha256:'+hashlib.sha256(raw).hexdigest()

def verify(folder,root=ROOT):
    def read(name):
        raw=(folder/(name+'.json')).read_bytes()
        if len(raw)>131072:raise ValueError('Evidence too large')
        return json.loads(raw)
    raw=(folder/'owner-activation.json').read_bytes()
    if hashlib.sha256(raw).hexdigest()!=ACTIVATION_SHA:raise ValueError('Owner activation differs')
    doc=json.loads(raw)
    if doc['source_commit']!=SOURCE:raise ValueError('Source differs')
    when=datetime.fromisoformat('2026-10-06T05:57:28.590243+00:00')
    _,keys=material(doc,root,when,unsigned=False)
    result=read('live-result');p=result['payload']
    SignedScopeStore('unused',None,keys)._verify(p,base64.b64decode(result['signature_base64'],validate=True),IDENTITIES['qa'],when)
    expected={'kind':'handoff003_qa_paid_recovery002_result','task_id':TASK,'source_commit':SOURCE,
        'role':'qa','producer_identity':IDENTITIES['qa'],'model_id':'gemini-3.7-flash','scope_digest':SCOPE_DIGEST,
        'request_digest':doc['allowance']['payload']['request_digest'],'transport_invocations':1,'actual_micro_usd':4979}
    if any(type(p.get(k)) is not type(v) or p.get(k)!=v for k,v in expected.items()):raise ValueError('Signed result bindings differ')
    output=base64.b64decode(result['output_base64'],validate=True)
    if sha(output)!=p['output_digest']:raise ValueError('QA output differs')
    builder=json.loads((root/'factory/evidence/handoff-003-live/builder-live-result.json').read_bytes())
    review=parse_review(output,root=root,role='qa',builder_response=base64.b64decode(builder['output_base64'],validate=True),candidate_commit='994719a384b7ac96abeb67e4b2addcab2deb4763')
    if review['verdict']!='ACCEPTED':raise ValueError('QA acceptance differs')
    row=read('attempt-observation')
    for field,value in {'PK':PK,'task_id':TASK,'source_commit':SOURCE,'contract_digest':SCOPE_DIGEST,'status':'COMPLETE',
        'reservation_status':'HELD','request_digest':p['request_digest'],'approval_digest':sha(canonical(doc['allowance']['payload'])),
        'output_digest':sha(canonical(result))}.items():
        if row.get(field)!={'S':value}:raise ValueError('Permanent claim differs')
    if row.get('reserved_micro_usd')!={'N':'250000'} or row.get('actual_micro_usd')!={'N':'4979'}:raise ValueError('Cost or hold differs')
    journal=read('live-journal')
    if [v['stage'] for v in journal]!=['PREPARATION_STARTED','LIVE_INVOKE_STARTED_NO_RETRY','LIVE_INVOKE_RETURNED','RESTORED_DISABLED']:
        raise ValueError('One-call journal differs')
    if journal[1]['activation_sha256']!=ACTIVATION_SHA or journal[2]['function_error'] is not None or journal[-1]['reserved_concurrency']!=0:
        raise ValueError('Invocation or shutdown differs')
    status=read('final-status')
    if (status['status']!='OBSERVED' or len(status['workers'])!=20 or not status['all_workers_disabled_observed'] or
        any(v.get('disabled_observed') is not True or v.get('reserved_concurrency')!=0 for v in status['workers'].values()) or
        status['task']!={'status':'OBSERVED','state':'PAUSED','version':0,'active_leases':0}):raise ValueError('Disabled observation differs')
    for name in ('handoff003_qa','handoff003_qa_recovery001'):
        if status['attempts'][name]!={'status':'STARTED','reservation_status':'HELD','reserved_micro_usd':250000,
            'reported_actual_micro_usd':None,'attempt_reusable':False}:raise ValueError('Prior hold differs')
    if status['attempts']['handoff003_qa_paid_recovery002']!={'status':'COMPLETE','reservation_status':'HELD','reserved_micro_usd':250000,
        'reported_actual_micro_usd':4979,'attempt_reusable':False}:raise ValueError('Recovery observation differs')
    return {'status':'HISTORICAL_PAID_QA_ACCEPTANCE_VERIFIED','model_attempts':1,'reported_micro_usd':4979,
        'unreconciled_prior_holds_micro_usd':500000,'attempt_reusable':False,'execution_authorized':False,'gate_authority':False,'invoice_verified':False}

if __name__=='__main__':print(json.dumps(verify(ROOT/FOLDER)))
