"""Isolated one-shot recovery workflow. Not wired to any deployed function."""
from factory_state.model import StateError
from factory_state.scope import canonical
from .qa_recovery002 import RecoveryAttemptStore,SCOPE_SHA256,digest
from .qa_recovery002_authorization import verify
from .pilot002_adapter import Pilot002Adapter
from .pilot002_packets import review_packet
from .pilot002_workflow import _fresh,Pilot002Stopped
from .pilot002_transport import ProviderHTTPStatusError


def run_once(envelope, *, root, source_commit, qualification, readiness,
             trusted_keys, builder_response, candidate_commit, store,
             load_credential, clock, enabled=False):
    if enabled is not True:raise StateError('Recovery workflow disabled')
    if type(store) is not RecoveryAttemptStore:raise StateError('Separate recovery store required')
    stage='preparation';raw=None;credential=None
    try:
        context={'root':root,'source_commit':source_commit,'builder_response':builder_response,
            'candidate_commit':candidate_commit}
        adapter=Pilot002Adapter(**context,role='qa',qualification=qualification,clock=clock,enabled=True)
        packet=review_packet(root,role='qa',builder_response=builder_response,candidate_commit=candidate_commit)
        request=adapter.build_request(packet)
        stage='authorization'
        args=verify(envelope,**context,request_bytes=request,pricing=adapter.pricing,
            readiness=readiness,trusted_keys=trusted_keys,now=clock())
        stage='reservation'
        if store.begin(**args)!=digest(request):raise StateError('Recovery claim differs')
        expiry=min(args['approval_expires_at'],args['pricing_expires_at'])
        stage='expiry_before_credential';previous=_fresh(clock(),args['now'],expiry)
        stage='credential';credential=load_credential()
        stage='expiry_before_provider';_fresh(clock(),previous,expiry)
        stage='provider'
        response=adapter.send_once(request_bytes=request,credential=credential,expected_request_digest=digest(request))
        credential=None;stage='response'
        if type(response) is not bytes or not 0<len(response)<=262144:raise StateError('Response exceeds bound')
        raw=response
        result=adapter.parse_response(raw,packet)
        if (result['model_id']!=packet['model_id'] or type(result['actual_micro_usd']) is not int or
                not 0<=result['actual_micro_usd']<=args['maximum_cost_micro_usd']):
            raise StateError('Recovery result identity or cost differs')
        from .pilot002_packets import parse_review
        output=parse_review(result['output_bytes'],root=root,role='qa',
            builder_response=builder_response,candidate_commit=candidate_commit)
        record={'status':'QA_RECOVERY002_COMPLETED_UNSIGNED','role':'qa',
            'source_commit':source_commit,'candidate_commit':candidate_commit,'model_id':packet['model_id'],
            'recovery_scope_digest':'sha256:'+SCOPE_SHA256,'request_digest':digest(request),
            'approval_digest':args['approval_digest'],'provider_response_digest':digest(raw),
            'actual_micro_usd':result['actual_micro_usd'],'output':output,'transport_invocations':1,
            'reservation_status':'HELD','gate_authority':False,'production_release_authorized':False}
        stage='completion'
        store.complete(request_digest=digest(request),approval_digest=args['approval_digest'],
            output_bytes=canonical(record),actual_micro_usd=result['actual_micro_usd'])
        return record
    except Exception as error:
        failure=Pilot002Stopped(stage,raw).review_failure('qa')
        if failure is not None:
            failure.update(status='QA_RECOVERY002_FAILED_NO_RETRY',recovery_scope_digest='sha256:'+SCOPE_SHA256)
            return failure
        status = error.http_status if type(error) is ProviderHTTPStatusError else None
        detail = ' (HTTP '+str(status)+')' if stage=='provider' and type(status) is int and 300<=status<=599 else ''
        raise StateError('QA recovery stopped at '+stage+detail+'; reconcile without retry') from None
    finally:
        credential=None
