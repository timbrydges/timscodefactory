"""Offline fresh QA scope preparation; no signing, AWS, claims, or generation."""
import base64
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'src'),str(ROOT/'scripts')]
from verify_handoff003_saved_evidence import verify
from factory_runtime.handoff003_protocols import request_bytes

SCOPE='factory/evidence/handoff-003-qa-recovery-001-scope.json'
SCOPE_SHA256='c957c44053926435005b53b7a789beaf5486ae736fea28c4e3840a4ec0975cb8'

def prepare(root,source_commit):
    if not isinstance(source_commit,str) or not re.fullmatch('[0-9a-f]{40}',source_commit):raise ValueError('Exact source required')
    raw=(root/SCOPE).read_bytes()
    if hashlib.sha256(raw).hexdigest()!=SCOPE_SHA256:raise ValueError('Recovery preparation scope differs')
    scope=json.loads(raw)
    for name,digest in scope['historical_files'].items():
        if hashlib.sha256((root/name).read_bytes()).hexdigest()!=digest:raise ValueError('Historical evidence differs')
    audit=verify(root/'factory/evidence/handoff-003-live',root=root)
    if audit['execution_authorized'] is not False or audit['qa_actual_cost_known'] is not False:raise ValueError('Historical outcome differs')
    if (scope['batch_reserved_after_micro_usd']!=scope['batch_reserved_before_micro_usd']+scope['approved_cap_micro_usd'] or
            scope['batch_reserved_after_micro_usd']>scope['batch_ceiling_micro_usd']):raise ValueError('Fresh budget exceeds batch')
    builder=json.loads((root/'factory/evidence/handoff-003-live/builder-live-result.json').read_bytes())
    request=request_bytes(root,role='qa',builder_response=base64.b64decode(builder['output_base64'],validate=True),candidate_commit=scope['candidate_commit'])
    return {'status':'PREPARED_NOT_AUTHORIZED','task_id':scope['task_id'],'source_commit':source_commit,
        'scope_digest':'sha256:'+SCOPE_SHA256,'request_digest':'sha256:'+hashlib.sha256(request).hexdigest(),
        'request_bytes':len(request),'historical_completed_cost_micro_usd':audit['reported_completed_micro_usd'],
        'prior_qa_charge_known':False,'prior_qa_hold_released':False,
        'new_cap_micro_usd':scope['approved_cap_micro_usd'],'batch_reserved_after_micro_usd':scope['batch_reserved_after_micro_usd'],
        'attempt_table':scope['new_attempt_table'],'attempt_key':scope['new_attempt_key'],
        'maximum_provider_calls':1,'retries':0,'transport_timeout_seconds':scope['transport_timeout_seconds'],
        'signed_allowance_present':False,'runtime_enabled':False,'provider_calls':0,'execution_authorized':False,'gate_authority':False}

if __name__=='__main__':
    if subprocess.check_output(['git','status','--porcelain'],cwd=ROOT,text=True).strip():raise RuntimeError('Clean reviewed source required')
    source=subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip()
    print(json.dumps(prepare(ROOT,source),indent=2))
