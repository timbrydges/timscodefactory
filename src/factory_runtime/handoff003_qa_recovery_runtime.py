"""Disabled QA recovery workflow; fresh authority, isolated claim and one transport."""
import base64
import copy
import json
from factory_state.model import StateError
from factory_state.scope import SignedScopeStore,canonical
from .handoff003_qa_recovery_authorization import verify,RecoveryAttemptStore,TASK,SCOPE_DIGEST
from .handoff003_protocols import request_bytes,parse_response
from .handoff003_receipts import IDENTITIES,sha
from .pilot002_transport import Pilot002Transport,ROUTES,ProviderTimeoutError,ProviderHTTPStatusError
from .pilot002_adapter import _cost
from .pilot002_workflow import _fresh

CANDIDATE='994719a384b7ac96abeb67e4b2addcab2deb4763'

class RecoveryTransport(Pilot002Transport):
    prepare=staticmethod(request_bytes)
    routes={**ROUTES,'qa':('generativelanguage.googleapis.com','/v1beta/models/gemini-3.7-flash:generateContent')}
    timeout_seconds=150
    def __init__(self,root,*,role,builder_response=None,candidate_commit=None,enabled=False):
        if role!='qa':raise StateError('Recovery transport is QA-only')
        super().__init__(root,role=role,builder_response=builder_response,candidate_commit=candidate_commit,enabled=enabled)

class RecoveryStopped(StateError):
    def __init__(self,stage,failure_code='unknown'):
        self.stage=stage;self.failure_code=failure_code
        super().__init__('QA recovery stopped at '+stage+'; retain hold; no retry')

def run_once(envelope,*,root,source_commit,qualification,readiness,trusted_keys,store,
             load_credential,sign_receipt,clock,enabled=False):
    if enabled is not True:raise StateError('QA recovery disabled')
    if type(store) is not RecoveryAttemptStore:raise StateError('Isolated recovery claim store required')
    envelope,qualification,readiness=copy.deepcopy((envelope,qualification,readiness))
    trusted_keys=dict(trusted_keys)
    stage='authorization';credential=None
    try:
        observed=clock()
        builder=json.loads((root/'factory/evidence/handoff-003-live/builder-live-result.json').read_bytes())
        builder_response=base64.b64decode(builder['output_base64'],validate=True)
        context={'role':'qa','builder_response':builder_response,'candidate_commit':CANDIDATE}
        request=request_bytes(root,**context)
        args=verify(envelope,root=root,source_commit=source_commit,qualification=qualification,readiness=readiness,
            trusted_keys=trusted_keys,now=observed,request_bytes=request)
        stage='reservation';expected=sha(request)
        if store.begin(**args)!=expected:raise StateError('Claim request differs')
        expiry=min(args['approval_expires_at'],args['pricing_expires_at'])
        stage='credential';previous=_fresh(clock(),observed,expiry);credential=load_credential()
        stage='provider';previous=_fresh(clock(),previous,expiry)
        raw=RecoveryTransport(root,**context,enabled=True).send_once(request_bytes=request,credential=credential,expected_request_digest=expected)
        credential=None;stage='response'
        result=parse_response(raw,root,**context);usage=result['usage']
        cost=_cost(usage['input_tokens'],usage['output_tokens_including_reasoning'],qualification)
        if (usage['input_tokens']>qualification['input_token_bound'] or
                cost>envelope['payload']['qualified_maximum_micro_usd']):raise StateError('Usage exceeds qualified maximum')
        stage='signing';now=_fresh(clock(),previous,expiry)
        payload={'kind':'handoff003_qa_recovery001_result','task_id':TASK,'role':'qa','producer_identity':IDENTITIES['qa'],
            'model_id':'gemini-3.7-flash','source_commit':source_commit,'scope_digest':SCOPE_DIGEST,
            'request_digest':expected,'output_digest':sha(result['output_bytes']),'provider_response_digest':sha(raw),
            'transport_invocations':1,'actual_micro_usd':cost,'issued_at':int(now.timestamp()),'expires_at':int(expiry.timestamp())}
        signature=sign_receipt(dict(payload),now=now)
        SignedScopeStore('unused',None,trusted_keys)._verify(payload,signature,IDENTITIES['qa'],now)
        signed={'payload':payload,'signature_base64':base64.b64encode(signature).decode(),
            'output_base64':base64.b64encode(result['output_bytes']).decode()}
        stage='completion';store.complete(role='qa',request_digest=expected,output_bytes=canonical(signed),actual_micro_usd=cost)
        return signed
    except Exception as error:
        failure='unknown'
        if stage=='provider':
            if isinstance(error,ProviderTimeoutError):failure='timeout'
            elif isinstance(error,ProviderHTTPStatusError) and type(error.http_status) is int and 300<=error.http_status<=599:failure='http_status_'+str(error.http_status)
        raise RecoveryStopped(stage,failure) from None
    finally:credential=None
