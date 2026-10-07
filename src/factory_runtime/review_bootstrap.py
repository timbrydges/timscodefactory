"""One permanent, paused fresh task; no signing, leasing, dispatch or providers."""
from datetime import datetime, timezone
import re

from factory_state.dynamodb import DynamoDBStateStore
from factory_state.model import TaskState, StateError, OWNER_IDENTITY
from factory_state.scope import canonical
from .review_material import PinnedReviewMaterial
from .review_provider_scope import FACTORY, TASK, PROVIDERS
from .review_provider_claims import TABLE as CLAIMS
from .worker import digest

TABLE='tims-software-factory-state'
PARTITION=f'FACTORY#{FACTORY}#TASK#{TASK}'


def validate(config, *, approved_digest, material, now):
    expected={'kind':'bounded_review004_paused_bootstrap','factory_id':FACTORY,'task_id':TASK,
        'source_commit':material.source_commit,'contract_digest':digest(material.contract_bytes),
        'owner_identity':OWNER_IDENTITY,'initial_state':'PAUSED','provider_calls':0}
    if (type(config)is not dict or set(config)!=set(expected)|{'not_before','expires_at','nonce'} or
            digest(canonical(config))!=approved_digest or
            any(type(config[k])is not type(v) or config[k]!=v for k,v in expected.items()) or
            any(type(config[k])is not int for k in ('not_before','expires_at')) or
            not 0<config['expires_at']-config['not_before']<=900 or
            not config['not_before']<=now.timestamp()<config['expires_at'] or
            type(config['nonce'])is not str or not re.fullmatch('[0-9a-f]{32}',config['nonce'])):
        raise StateError('exact current paused bootstrap approval required')
    material.evidence('inspector',clock=lambda:now)


def run(config, *, approved_digest, material, db, sts, clock, enabled=False):
    if enabled is not True or type(material)is not PinnedReviewMaterial:
        raise StateError('paused bootstrap disabled or material missing')
    if (getattr(getattr(db,'meta',None),'endpoint_url',None)!='https://dynamodb.ca-central-1.amazonaws.com' or
            getattr(getattr(getattr(db,'meta',None),'config',None),'retries',{}).get('total_max_attempts')!=1):
        raise StateError('bootstrap requires regional no-retry DynamoDB')
    validate(config,approved_digest=approved_digest,material=material,now=clock())
    caller=sts.get_caller_identity()
    if caller.get('Account')!='666730517561' or not caller.get('Arn'):
        raise StateError('bootstrap account differs')
    at=datetime.fromtimestamp(config['not_before'],timezone.utc)
    state=TaskState(FACTORY,TASK,'PAUSED',0,at,OWNER_IDENTITY)
    row=DynamoDBStateStore._serialize_state(state);row['SK']={'S':'STATE'}
    marker={'PK':{'S':PARTITION},'SK':{'S':'BOOTSTRAP#bounded-review-004'},
        'approval_digest':{'S':approved_digest},'source_commit':{'S':material.source_commit},
        'contract_digest':{'S':digest(material.contract_bytes)}}
    audit={'PK':{'S':PARTITION},'SK':{'S':'EVENT#'+at.isoformat()+'#bounded-review-bootstrap'},
        'event_type':{'S':'TASK_BOOTSTRAPPED'},'actor_identity':{'S':OWNER_IDENTITY},
        'caller_arn':{'S':caller['Arn']},'to_state':{'S':'PAUSED'},'to_version':{'N':'0'},
        'approval_digest':{'S':approved_digest}}
    expected=(row,marker,audit)
    def read():
        return tuple(db.get_item(TableName=TABLE,Key={k:item[k] for k in ('PK','SK')},
            ConsistentRead=True).get('Item') for item in expected)
    observed=read()
    if any(observed):
        if observed!=expected:raise StateError('task or bootstrap history already exists; never reset')
        return {'status':'RECONCILED_PAUSED_BOOTSTRAP','writes':0,'provider_calls':0}
    validate(config,approved_digest=approved_digest,material=material,now=clock())
    transaction=[{'Put':{'TableName':TABLE,'Item':item,
        'ConditionExpression':'attribute_not_exists(PK) AND attribute_not_exists(SK)'}} for item in expected]
    transaction += [{'ConditionCheck':{'TableName':CLAIMS,'Key':{'PK':{'S':'BOUNDED_REVIEW#004#ROLE#'+role}},
        'ConditionExpression':'attribute_not_exists(PK)'}} for role in PROVIDERS]
    try:db.transact_write_items(TransactItems=transaction)
    except Exception:
        if read()!=expected:raise StateError('bootstrap outcome unresolved; reconcile without retry') from None
    if read()!=expected:raise StateError('bootstrap readback differs; never retry')
    return {'status':'PAUSED_BOOTSTRAP_VERIFIED','state':'PAUSED','version':0,'writes':3,
        'claim_writes':0,'provider_calls':0,'leases':0,'dispatches':0}
