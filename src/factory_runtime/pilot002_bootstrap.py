"""One new PAUSED task; no provider, signer, scheduler or dispatch capability."""
import hashlib
import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path

from factory_state.dynamodb import DynamoDBStateStore
from factory_state.model import TaskState, StateError, CONTROLLER_IDENTITY

TASK='safe-workspace-fingerprint-001'
FACTORY='tims-software-factory'
PARTITION=f'FACTORY#{FACTORY}#TASK#{TASK}'
TABLE='tims-software-factory-state'
CONTRACT='factory/autonomy/pilot-002-contract.json'
APPROVAL='factory/evidence/pilot-002-task-budget-approval.json'
PINNED={CONTRACT:'eb3bccd8ee7cdc29cd498b4cd93d11039dc55221d42c1115dba7a7c660f7ebbf',
        APPROVAL:'0fd5790ed4ce9d4648cf3da27d640eafe6a5fe34b02e977738be61f468acbd45'}
ENABLED='FACTORY_PILOT002_BOOTSTRAP_ENABLED'
CONFIG='FACTORY_PILOT002_BOOTSTRAP_CONFIG'


def facts(root):
    values=[]
    for name,expected in PINNED.items():
        raw=(root/name).read_bytes()
        if hashlib.sha256(raw).hexdigest()!=expected:
            raise StateError('Pilot 002 contract or task/budget approval differs')
        values.append(json.loads(raw))
    return values


def boundary(event, *, root, env, now):
    facts(root)
    try:
        commit=json.loads((root/'BUILD.json').read_bytes())['source_commit']
        config=json.loads(env[CONFIG])
        expected={'approved':True,'owner_identity':'tim_brydges','operation':'pilot-002-bootstrap',
                  'source_commit':commit,'task_id':TASK,'contract_sha256':PINNED[CONTRACT]}
        if (env.get(ENABLED)!='true' or
            env.get('FACTORY_AUTONOMY_CONTROLLER_ENABLED')!='false' or
            any(env.get(flag,'false')!='false' for flag in ('FACTORY_SECURITY_GATE_ENABLED','FACTORY_QA_GATE_ENABLED')) or
            not re.fullmatch('[0-9a-f]{40}',commit) or set(config)!=set(expected)|{'not_before','expires_at','nonce'} or
            any(type(config.get(k)) is not type(v) or config[k]!=v for k,v in expected.items()) or
            type(config['not_before']) is not int or type(config['expires_at']) is not int or
            not 0<config['expires_at']-config['not_before']<=3600 or
            now.tzinfo is None or not config['not_before']<=now.timestamp()<config['expires_at'] or
            not isinstance(config['nonce'],str) or not re.fullmatch('[0-9a-f]{32}',config['nonce']) or
            event!={'kind':'bootstrap_pilot_002','source_commit':commit,'task_id':TASK,'nonce':config['nonce']}):
            raise StateError('Pilot 002 bootstrap is disabled, expired or not exactly authorized')
    except (KeyError,TypeError,ValueError,AttributeError):
        raise StateError('Pilot 002 bootstrap configuration malformed') from None
    return config


def items(config):
    at=datetime.fromtimestamp(config['not_before'],timezone.utc)
    state=TaskState(FACTORY,TASK,'PAUSED',0,at,CONTROLLER_IDENTITY)
    row=DynamoDBStateStore._serialize_state(state); row['SK']={'S':'STATE'}
    marker={'PK':{'S':PARTITION},'SK':{'S':'BOOTSTRAP#pilot-002'},
            'source_commit':{'S':config['source_commit']},'contract_sha256':{'S':PINNED[CONTRACT]},
            'approval_sha256':{'S':PINNED[APPROVAL]},'nonce':{'S':config['nonce']}}
    audit={'PK':{'S':PARTITION},'SK':{'S':f'EVENT#{at.isoformat()}#pilot-002-bootstrap'},
           'actor_identity':{'S':CONTROLLER_IDENTITY},'event_type':{'S':'TASK_BOOTSTRAPPED'},
           'to_state':{'S':'PAUSED'},'to_version':{'N':'0'},
           'details':{'S':json.dumps({'contract_sha256':PINNED[CONTRACT],
               'owner_task_budget_approval_sha256':PINNED[APPROVAL],
               'live_execution_authorized':False},sort_keys=True)}}
    return row,marker,audit


def run(event, *, root, env, db, sts, clock):
    config=boundary(event,root=root,env=env,now=clock())
    caller=sts.get_caller_identity()
    prefix='arn:aws:sts::666730517561:assumed-role/tims-software-factory-autonomy-controller-disabled/'
    arn=caller.get('Arn','')
    if caller.get('Account')!='666730517561' or not isinstance(arn,str) or not arn.startswith(prefix) or not arn[len(prefix):] or '/' in arn[len(prefix):]:
        raise StateError('Pilot 002 bootstrap requires the exact controller cloud identity')
    expected=items(config)
    def read():
        return tuple(db.get_item(TableName=TABLE,Key={k:item[k] for k in ('PK','SK')},
                     ConsistentRead=True).get('Item') for item in expected)
    existing=read()
    if any(existing):
        if existing!=expected:
            raise StateError('Pilot 002 already exists or evidence differs; never reset history')
        return {'status':'RECONCILED_EXISTING_PAUSED_TASK','state':'PAUSED','version':0,'writes':0}
    boundary(event,root=root,env=env,now=clock())
    # All three conditions must succeed atomically. A marker prevents resurrection
    # even if a separate actor later removes the STATE row. Never retry uncertainty.
    try:
        db.transact_write_items(ClientRequestToken='p002-'+config['nonce'][:31],TransactItems=[
            {'Put':{'TableName':TABLE,'Item':item,
                    'ConditionExpression':'attribute_not_exists(PK) AND attribute_not_exists(SK)'}} for item in expected])
    except Exception:
        raise StateError('Pilot 002 bootstrap outcome uncertain; reconcile read-only, do not repeat') from None
    if read()!=expected:
        raise StateError('Pilot 002 bootstrap verification differs; reconcile read-only')
    return {'status':'BOOTSTRAPPED_PAUSED_VERIFIED','task_id':TASK,'state':'PAUSED','version':0,
            'writes':3,'model_calls':0,'leases':0,'budget_reserved':False,'live_execution_authorized':False}


def handler(event,context):
    root=Path(os.environ.get('LAMBDA_TASK_ROOT','/var/task'))
    clock=lambda:datetime.now(timezone.utc)
    boundary(event,root=root,env=os.environ,now=clock())
    import boto3
    from botocore.config import Config
    session=boto3.Session(region_name='ca-central-1')
    config=Config(connect_timeout=5,read_timeout=10,retries={'total_max_attempts':1,'mode':'standard'})
    return run(event,root=root,env=os.environ,clock=clock,
               db=session.client('dynamodb',config=config),sts=session.client('sts',config=config))
