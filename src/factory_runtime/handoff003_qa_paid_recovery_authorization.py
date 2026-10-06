"""Fresh QA-only authorization and permanent claim, separate from failed handoff003."""
import base64
import copy
from datetime import datetime,timezone
import hashlib
from factory_state.model import OWNER_IDENTITY,StateError
from factory_state.scope import SignedScopeStore,canonical
from .pilot002_authorization import _exact,_window,_hash
from .pilot002_attempts import _PermanentAttemptStore
from .pilot002_adapter import _cost

TASK='authenticated-handoff-003-qa-recovery-002'
TABLE='tims-factory-handoff-003-qa-recovery-002-attempts'
PK='HANDOFF#003#QA_RECOVERY#002'
KIND='handoff003_qa_paid_recovery002_exact_request_allowance'
SCOPE_DIGEST='sha256:aefdd429b0c6b6492369e3afa3d08e04d3df5edd4e3f1532ce43a68a9c98afeb'

def digest(value):return 'sha256:'+hashlib.sha256(canonical(value)).hexdigest()

def key(role):
    if role!='qa':raise StateError('Recovery is QA-only')
    return {'PK':{'S':PK}}

class RecoveryAttemptStore(_PermanentAttemptStore):
    table=TABLE
    task=TASK
    contract_digest=SCOPE_DIGEST
    row_key=staticmethod(key)

def bindings(root,source_commit):
    # Historical signatures prove prior results only. Fresh authority is below.
    from scripts.prepare_handoff003_qa_paid_recovery import prepare
    prepared=prepare(root,source_commit)
    if prepared['task_id']!=TASK or prepared['scope_digest']!=SCOPE_DIGEST:raise StateError('Recovery preparation differs')
    return {'task_id':TASK,'role':'qa','model_id':'gemini-3.7-flash','source_commit':source_commit,
        'scope_digest':SCOPE_DIGEST,'request_digest':prepared['request_digest']}

def draft(*,root,source_commit,qualification,readiness,now,issued_at,expires_at):
    """Prepare unsigned material; cannot claim, sign, or invoke anything."""
    if not isinstance(now,datetime) or now.tzinfo is None:raise StateError('Aware current clock required')
    bound=bindings(root,source_commit)
    q=qualification
    expected={'kind':'handoff003_qa_paid_recovery002_rate_qualification',**bound,
        'complete_request_bound_qualified':True,'output_token_bound':4096}
    extra={'input_token_bound','input_micro_usd_per_million','output_micro_usd_per_million','issued_at','expires_at','evidence_digest'}
    if (not _exact(q,expected,extra) or not _window(q,now,3600) or not _hash(q['evidence_digest']) or
            type(q['input_token_bound']) is not int or not 0<q['input_token_bound']<=32768 or
            any(type(q[k]) is not int or not 0<=q[k]<=1000000000 for k in ('input_micro_usd_per_million','output_micro_usd_per_million'))):
        raise StateError('Recovery pricing qualification differs')
    maximum=_cost(q['input_token_bound'],4096,q)
    if not 0<maximum<=250000:raise StateError('Recovery qualified maximum exceeds cap')
    expected={'kind':'handoff003_qa_paid_recovery002_readiness',**bound,'credential_route_verified':True,
        'model_metadata_verified':True,'repository_binding_verified':True,'single_attempt_failure_risk_accepted':True,
        'paid_tier_verified':True,'google_project_id':'gen-lang-client-0247455615'}
    if (not _exact(readiness,expected,{'issued_at','expires_at','evidence_digest'}) or
            not _window(readiness,now,3600) or not _hash(readiness['evidence_digest'])):raise StateError('Recovery readiness differs')
    payload={'kind':KIND,'owner_identity':OWNER_IDENTITY,**bound,'attempt_table':TABLE,'attempt_key':PK,
        'qualification_digest':digest(q),'readiness_digest':digest(readiness),'qualified_maximum_micro_usd':maximum,
        'approved_cap_micro_usd':250000,'reserved_micro_usd':250000,'maximum_provider_calls':1,'retries':0,
        'transport_timeout_seconds':150,'worker_timeout_seconds':240,'historical_scope_grants_authority':False,
        'prior_hold_release_authorized':False,'task_state_writes':0,'gate_authority':False,
        'production_release_authorized':False,'issued_at':issued_at,'expires_at':expires_at}
    if not _window(payload,now,3600) or expires_at>min(q['expires_at'],readiness['expires_at']):raise StateError('Recovery allowance window differs')
    return payload

def verify(envelope,*,root,source_commit,qualification,readiness,trusted_keys,now,request_bytes):
    """Only a new exact owner signature grants a new, isolated claim permission."""
    envelope,qualification,readiness=copy.deepcopy((envelope,qualification,readiness))
    if type(envelope) is not dict or set(envelope)!={'payload','signature'}:raise StateError('Fresh recovery signature required')
    payload=envelope['payload']
    if type(payload) is not dict:raise StateError('Recovery payload object required')
    expected=draft(root=root,source_commit=source_commit,qualification=qualification,readiness=readiness,now=now,
        issued_at=payload.get('issued_at'),expires_at=payload.get('expires_at'))
    if not _exact(payload,expected,set()):raise StateError('Exact fresh recovery allowance required')
    if (type(request_bytes) is not bytes or not 0<len(request_bytes)<=65536 or
            'sha256:'+hashlib.sha256(request_bytes).hexdigest()!=payload['request_digest']):
        raise StateError('Recovery request bytes differ from signed scope')
    try:
        encoded=envelope['signature']
        if type(encoded) is not str or len(encoded)!=88:raise ValueError()
        signature=base64.b64decode(encoded,validate=True)
        SignedScopeStore('unused',None,dict(trusted_keys))._verify(payload,signature,OWNER_IDENTITY,now)
    except Exception:raise StateError('Fresh recovery owner signature invalid') from None
    return {'role':'qa','request_bytes':request_bytes,'source_commit':source_commit,'approval_digest':digest(payload),
        'pricing_digest':digest(qualification),'now':now,
        'approval_expires_at':datetime.fromtimestamp(payload['expires_at'],timezone.utc),
        'pricing_expires_at':datetime.fromtimestamp(qualification['expires_at'],timezone.utc)}
