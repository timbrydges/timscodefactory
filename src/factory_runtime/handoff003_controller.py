"""Read-only next-stage decision; runtime still requires its own signed allowance.

A non-atomic observation can become stale. NEXT_ROLE is advisory only; the
runtime's conditional permanent claim remains the concurrency authority.
"""
from factory_state.model import StateError
from factory_state.scope import canonical
from .handoff003_attempts import ROLES,key
from .handoff003_packets import TASK
from .handoff003_receipts import sha,verify_chain,verify_predecessors


def decide(*, attempts, envelopes, root, trusted_keys, source_commit,
           candidate_commit, request_digests, now, verify_executed_tests):
    base={'gate_authority':False,'execution_authorized':False,'worker_invocations':0}
    def stop(reason):return {**base,'status':'STOPPED_NO_RETRY','reason':reason,'next_role':None}
    if not isinstance(attempts,dict) or set(attempts)!=set(ROLES) or not isinstance(envelopes,dict):
        return stop('Incomplete observations')
    completed=[];waiting=None
    for role in ROLES:
        row=attempts[role]
        if row is None:
            if waiting is None:waiting=role
            continue
        if waiting is not None:return stop('Out-of-order attempt')
        try:
            if (row['PK']!=key(role)['PK'] or row['task_id']['S']!=TASK or
                    row['role']['S']!=role or row['source_commit']['S']!=source_commit or
                    row['reservation_status']['S']!='HELD' or
                    row['reserved_micro_usd']['N']!='250000'):
                return stop('Attempt identity or hold differs')
            if row['status']['S']!='COMPLETE':return stop('Attempt consumed or outcome uncertain')
            envelope=envelopes[role]
            if (row['request_digest']['S']!=request_digests[role] or
                    row['output_digest']['S']!=sha(canonical(envelope)) or
                    row['actual_micro_usd']['N']!=str(envelope['payload']['actual_micro_usd'])):
                return stop('Attempt and receipt differ')
        except (KeyError,TypeError,ValueError):return stop('Malformed observation')
        completed.append(role)
    if set(envelopes)!=set(completed):return stop('Receipt exists without completed attempt')
    if not isinstance(request_digests,dict) or set(request_digests)!=set(completed):
        return stop('Unexpected request bindings')
    context=dict(root=root,trusted_keys=trusted_keys,source_commit=source_commit,
        candidate_commit=candidate_commit,request_digests=request_digests,now=now)
    try:
        if len(completed)==3:
            result=verify_chain(envelopes,verify_executed_tests=verify_executed_tests,**context)
            return {**base,'status':'COMPLETED_NO_DISPATCH','next_role':None,
                'receipt_digests':result['receipt_digests'],
                'reported_actual_micro_usd':result['reported_actual_micro_usd']}
        if completed:
            verify_predecessors(envelopes,next_role=waiting,**context)
        elif waiting!='builder':return stop('Missing initial stage')
    except (StateError,ValueError,TypeError,KeyError):
        return stop('Signature, scope, time or independent tests rejected')
    return {**base,'status':'NEXT_ROLE_REQUIRES_SIGNED_ALLOWANCE','next_role':waiting}
