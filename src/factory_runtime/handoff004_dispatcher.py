"""One source-bound stage per invocation, with no signing or provider credentials."""
import base64
from datetime import datetime,timezone
import hashlib
import json
import os
from pathlib import Path
import re
from factory_state.model import StateError
from factory_state.scope import canonical
from .handoff004_attempts import TABLE as ATTEMPTS,ROLES,key
from .handoff004_dispatch import dispatch_once,TABLE
from .handoff004_entrypoint import load_activation
from .handoff004_packets import TASK,parse_builder,facts
from .handoff004_controller import decide
from .handoff004_receipts import sha
from .pilot002_entrypoint import _read,_pairs

NAME='tims-factory-handoff-004-dispatcher'
ARN='arn:aws:lambda:ca-central-1:666730517561:function:'+NAME+':'
CONFIG='HANDOFF004_DISPATCH.json'


def verify_tests(proof, *, root, source, candidate, envelopes, commit, digest):
    if type(proof)is not dict:return False
    try:
        parsed=parse_builder(base64.b64decode(envelopes['builder']['output_base64'],validate=True),root=root)
        return (commit==candidate and digest==parsed['candidate_digest'] and
            parsed['files']==facts(root)[1]['files'] and proof['source_commit']==source and
            proof['candidate_commit']==candidate and proof['runtime']=='python3.12-linux' and
            proof['python_version'].startswith('3.12.') and proof['exit_code']==0 and
            proof['credentials_in_environment'] is False and
            re.search(r'Ran 17 tests in [0-9.]+s\n\nOK\n$',proof['stderr']) is not None and
            'skipped' not in proof['stderr'].lower() and
            proof['files']=={n:hashlib.sha256(t.encode()).hexdigest() for n,t in parsed['files'].items()})
    except (KeyError,TypeError,ValueError,StateError):return False


def run(event, context, *, root, env, clock, clients):
    if env.get('FACTORY_HANDOFF004_DISPATCH_ENABLED')!='true':raise StateError('Dispatcher disabled')
    arn=getattr(context,'invoked_function_arn','')
    if (not isinstance(arn,str) or not arn.startswith(ARN) or not re.fullmatch('[1-9][0-9]*',arn[len(ARN):]) or
            env.get('AWS_REGION')!='ca-central-1' or env.get('AWS_LAMBDA_FUNCTION_NAME')!=NAME or
            context.get_remaining_time_in_millis()<210000):
        raise StateError('Exact dispatcher version and sufficient runtime required')
    raw=_read(root,CONFIG,262144);digest=hashlib.sha256(raw).hexdigest()
    if env.get('FACTORY_HANDOFF004_DISPATCH_SHA256')!=digest:raise StateError('Dispatch configuration differs')
    config=json.loads(raw,object_pairs_hook=_pairs)
    if type(config)is not dict or set(config)!={'source_commit','pin','candidate_commit','test_proof'}:
        raise StateError('Dispatch configuration schema differs')
    source=config['source_commit'];pin=config['pin'];candidate=config['candidate_commit']
    if (json.loads(_read(root,'BUILD.json',1024))!={'source_commit':source} or
            event!={'kind':'handoff004_dispatch_once','source_commit':source,'dispatch_sha256':digest} or
            not isinstance(candidate,str) or not re.fullmatch('[0-9a-f]{40}',candidate)):
        raise StateError('Dispatch event or candidate binding differs')
    doc,keys,_,_,_=load_activation(root,{'FACTORY_HANDOFF004_ROLE':pin['role'],
        'FACTORY_HANDOFF004_ACTIVATION_SHA256':pin['activation_sha256']},clock())
    if doc['source_commit']!=source or pin['source_commit']!=source:raise StateError('Dispatch source differs')
    if pin['role']=='qa':
        candidate_digest=parse_builder(base64.b64decode(doc['predecessors']['builder']['output_base64'],validate=True),root=root)['candidate_digest']
        if not verify_tests(config['test_proof'],root=root,source=source,candidate=candidate,
                envelopes=doc['predecessors'],commit=candidate,digest=candidate_digest):
            raise StateError('Independent candidate test evidence required before QA dispatch')
    sts,db,lam=clients()
    identity=sts.get_caller_identity()
    if (identity.get('Account')!='666730517561' or not identity.get('Arn','').startswith(
            'arn:aws:sts::666730517561:assumed-role/'+NAME+'/')):
        raise StateError('Exact dispatcher role required')
    attempts={r:db.get_item(TableName=ATTEMPTS,Key=key(r),ConsistentRead=True).get('Item') for r in ROLES}
    envelopes=dict(doc['predecessors'] or {});requests=dict(doc['predecessor_request_digests'] or {})
    # Recover durable evidence, never repeat an invocation to recover a response.
    for role in ROLES:
        row=db.get_item(TableName=TABLE,Key={'PK':{'S':'HANDOFF#004#CONTROLLER#'+TASK+'#'+role}},ConsistentRead=True).get('Item')
        if row and row.get('status',{}).get('S')=='COMPLETE':
            encoded=row['signed_receipt']['S'].encode()
            if len(encoded)>350000 or sha(encoded)!=row['output_digest']['S']:raise StateError('Stored evidence differs')
            envelope=json.loads(encoded,object_pairs_hook=_pairs)
            if role in envelopes and envelopes[role]!=envelope:raise StateError('Stored predecessor differs')
            envelopes[role]=envelope;requests[role]=row['request_digest']['S']
    args=dict(attempts=attempts,envelopes=envelopes,root=root,trusted_keys=keys,source_commit=source,
        candidate_commit=candidate,request_digests=requests,verify_executed_tests=lambda commit,digest:
            verify_tests(config['test_proof'],root=root,source=source,candidate=candidate,
                envelopes=envelopes,commit=commit,digest=digest))
    decision=decide(**args,now=clock())
    if decision['status']!='NEXT_ROLE_REQUIRES_SIGNED_ALLOWANCE':return decision
    if pin['role'] in envelopes:
        return {'status':'STAGE_ALREADY_COMPLETE','role':pin['role'],'envelope':envelopes[pin['role']],
            'worker_invocations':0,'execution_authorized':False,'gate_authority':False}
    return dispatch_once(context=args,pin=pin,activation_root=root,db=db,lam=lam,clock=clock,enabled=True)


def handler(event,context):
    def clients():
        import boto3
        from botocore.config import Config
        s=boto3.Session(region_name='ca-central-1')
        cfg=Config(retries={'total_max_attempts':1},connect_timeout=5,read_timeout=200)
        return tuple(s.client(service,config=cfg) for service in ('sts','dynamodb','lambda'))
    return run(event,context,root=Path(__file__).resolve().parents[1],env=os.environ,
        clock=lambda:datetime.now(timezone.utc),clients=clients)
