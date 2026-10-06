"""Disabled-by-default, permanent one-shot dispatch of an already signed role.

No signing, credential reads, model requests, configuration changes or retries.
The caller owns freshly observed inputs; role runtime claims remain authoritative.
"""
import base64
import json
import re
from factory_state.model import StateError
from factory_state.scope import canonical
from .handoff003_controller import decide
from .handoff003_entrypoint import load_activation
from .handoff003_packets import TASK
from .handoff003_receipts import verify_predecessors,verify_chain,sha

TABLE='tims-factory-handoff-003-controller-dispatch'
ROLES=('builder','inspector','qa')


def dispatch_once(*, context, pin, activation_root, db, lam, clock, enabled=False):
    if enabled is not True:raise StateError('Handoff controller dispatch disabled')
    context={**context,'now':clock()}
    decision=decide(**context)
    if decision['status']!='NEXT_ROLE_REQUIRES_SIGNED_ALLOWANCE':return decision
    role=decision['next_role']
    if (type(pin)is not dict or set(pin)!={'role','version_arn','code_sha256','activation_sha256','source_commit'} or
            pin['role']!=role or pin['source_commit']!=context['source_commit']):
        raise StateError('Exact deployment pin required')
    prefix='arn:aws:lambda:ca-central-1:666730517561:function:tims-factory-handoff-003-'+role+':'
    arn=pin['version_arn']
    if (not isinstance(arn,str) or not arn.startswith(prefix) or
            not re.fullmatch('[1-9][0-9]*',arn[len(prefix):]) or
            not isinstance(pin['activation_sha256'],str) or not re.fullmatch('[0-9a-f]{64}',pin['activation_sha256'])):
        raise StateError('Immutable exact role version required')
    try:
        if len(base64.b64decode(pin['code_sha256'],validate=True))!=32:raise ValueError('hash')
    except (ValueError,TypeError):raise StateError('Package digest required') from None
    for client in (db,lam):
        if client.meta.config.retries.get('total_max_attempts')!=1:
            raise StateError('Single-attempt AWS clients required')
    env={'FACTORY_HANDOFF003_ENABLED':'true','FACTORY_HANDOFF003_ROLE':role,
         'FACTORY_HANDOFF003_ACTIVATION_SHA256':pin['activation_sha256']}
    def authorize():
        doc,keys,_,request,previous=load_activation(activation_root,env,clock())
        if (doc['source_commit']!=pin['source_commit'] or
                keys!=context['trusted_keys'] or
                doc['predecessors']!=(context['envelopes'] if role!='builder' else None) or
                doc['predecessor_request_digests']!=(context['request_digests'] if role!='builder' else None) or
                doc['candidate_commit']!=(context['candidate_commit'] if role!='builder' else None)):
            raise StateError('Signed scope or trusted enrollment differs')
        return request
    request=authorize()
    conf=lam.get_function_configuration(FunctionName=arn)
    if (conf.get('CodeSha256')!=pin['code_sha256'] or conf.get('Version')!=arn[len(prefix):] or
            conf.get('FunctionName')!='tims-factory-handoff-003-'+role or
            conf.get('Environment',{}).get('Variables')!=env or
            conf.get('Handler')!='factory_runtime.handoff003_entrypoint.handler'):
        raise StateError('Immutable runtime differs from reviewed package')
    if authorize()!=request:raise StateError('Authorization changed during preflight')
    claim={'PK':{'S':'HANDOFF#003#CONTROLLER#'+TASK+'#'+role}}
    # No read-then-write eligibility decision can replace this conditional claim.
    try:
        db.put_item(TableName=TABLE,Item={**claim,'status':{'S':'STARTED'},
            'request_digest':{'S':request},'version_arn':{'S':arn},
            'activation_sha256':{'S':pin['activation_sha256']}},ConditionExpression='attribute_not_exists(PK)')
    except Exception:
        return {'status':'DISPATCH_CONSUMED_OR_UNCERTAIN','next_role':None,'worker_invocations':0,
            'execution_authorized':False,'gate_authority':False}
    try:
        reply=lam.invoke(FunctionName=arn,InvocationType='RequestResponse',Payload=canonical({
            'kind':'handoff003_run_once','source_commit':pin['source_commit'],
            'activation_sha256':pin['activation_sha256']}))
        raw=reply['Payload'].read(524289)
        if reply.get('FunctionError') or not 0<len(raw)<=524288:raise ValueError('Runtime failure')
        envelope=json.loads(raw)
        envelopes={**context['envelopes'],role:envelope}
        verify_context={k:context[k] for k in ('root','trusted_keys','source_commit','candidate_commit')}
        verify_context.update(request_digests={**context['request_digests'],role:request},now=clock())
        if role=='qa':verify_chain(envelopes,verify_executed_tests=context['verify_executed_tests'],**verify_context)
        else:verify_predecessors(envelopes,next_role=ROLES[ROLES.index(role)+1],**verify_context)
        # Keep the signed result with the permanent claim. A lost caller response
        # must not require another worker invocation to recover the evidence.
        encoded=canonical(envelope)
        if len(encoded)>350000:raise ValueError('Receipt exceeds durable evidence limit')
        db.update_item(TableName=TABLE,Key=claim,
            UpdateExpression='SET #s = :complete, output_digest = :output, signed_receipt = :receipt',
            ConditionExpression='#s = :started AND request_digest = :request',
            ExpressionAttributeNames={'#s':'status'},ExpressionAttributeValues={
                ':complete':{'S':'COMPLETE'},':started':{'S':'STARTED'},
                ':request':{'S':request},':output':{'S':sha(encoded)},
                ':receipt':{'S':encoded.decode('utf-8')}})
        return {'status':'SIGNED_RESULT_OBSERVED','role':role,'envelope':envelope,
            'worker_invocations':1,'gate_authority':False,'execution_authorized':False}
    except Exception:
        return {'status':'DISPATCH_OUTCOME_UNCERTAIN_NO_RETRY','next_role':None,
            'worker_invocations':1,'gate_authority':False,'execution_authorized':False}
