"""Inert actual-role permission proof: impossible conditions, no worker calls."""
import json
import os
from pathlib import Path
import re
from factory_state.model import StateError
from .handoff003_dispatcher import NAME,ARN
from .handoff003_dispatch import TABLE
from .handoff003_attempts import TABLE as ATTEMPTS,key,ROLES
from .handoff003_packets import TASK


def probe(db):
    from botocore.exceptions import ClientError
    for role in ROLES:
        if db.get_item(TableName=ATTEMPTS,Key=key(role),ConsistentRead=True).get('Item'):
            raise StateError('Fresh commissioning attempt must be absent')
        claim={'PK':{'S':'HANDOFF#003#CONTROLLER#'+TASK+'#'+role}}
        if db.get_item(TableName=TABLE,Key=claim,ConsistentRead=True).get('Item'):
            raise StateError('Fresh dispatcher claim must be absent')
        try:
            db.put_item(TableName=TABLE,Item=claim,
                ConditionExpression='attribute_exists(PK) AND attribute_not_exists(PK)')
        except ClientError as error:
            if error.response['Error']['Code']!='ConditionalCheckFailedException':raise StateError('Own claim permission unverified') from None
        else:raise StateError('Impossible condition unexpectedly succeeded')
        try:
            db.update_item(TableName=TABLE,Key=claim,UpdateExpression='SET #s=:s',
                ExpressionAttributeNames={'#s':'status'},ExpressionAttributeValues={':s':{'S':'INERT_PROBE'}},
                ConditionExpression='attribute_exists(PK) AND attribute_not_exists(PK)')
        except ClientError as error:
            if error.response['Error']['Code']!='ConditionalCheckFailedException':raise StateError('Own completion permission unverified') from None
        else:raise StateError('Impossible update unexpectedly succeeded')
    try:
        db.put_item(TableName=TABLE,Item={'PK':{'S':'UNAUTHORIZED_DISPATCH_PROBE'}},
            ConditionExpression='attribute_exists(PK) AND attribute_not_exists(PK)')
    except ClientError as error:
        if error.response['Error']['Code']!='AccessDeniedException':raise StateError('Other claim permission is not denied') from None
    else:raise StateError('Other claim permission unexpectedly succeeded')
    return {'status':'DISPATCH_PERMISSION_CANARY_VERIFIED','own_claim_conditions':'REJECTED',
        'other_claim':'ACCESS_DENIED','state_writes':0,'worker_invocations':0,'model_calls':0}


def handler(event,context):
    if (os.environ.get('FACTORY_HANDOFF003_DISPATCH_ENABLED')!='false' or
            os.environ.get('FACTORY_HANDOFF003_MODE')!='permissions_canary'):
        raise StateError('Explicit inert dispatcher mode required')
    arn=getattr(context,'invoked_function_arn','')
    if (not isinstance(arn,str) or not arn.startswith(ARN) or not re.fullmatch('[1-9][0-9]*',arn[len(ARN):]) or
            os.environ.get('AWS_REGION')!='ca-central-1' or os.environ.get('AWS_LAMBDA_FUNCTION_NAME')!=NAME):
        raise StateError('Exact canary version required')
    source=json.loads((Path(__file__).resolve().parents[1]/'BUILD.json').read_bytes())['source_commit']
    if event!={'kind':'handoff003_dispatch_permissions_only','source_commit':source}:raise StateError('Canary source differs')
    import boto3
    from botocore.config import Config
    s=boto3.Session(region_name='ca-central-1');cfg=Config(retries={'total_max_attempts':1})
    identity=s.client('sts',config=cfg).get_caller_identity()
    if identity.get('Account')!='666730517561' or not identity.get('Arn','').startswith('arn:aws:sts::666730517561:assumed-role/'+NAME+'/'):
        raise StateError('Exact dispatcher identity required')
    return {**probe(s.client('dynamodb',config=cfg)),'source_commit':source}
