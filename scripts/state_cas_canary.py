"""One model-free state persistence canary; fixed synthetic rows only, retained for audit."""
import argparse
import json
import sys
from dataclasses import replace
from datetime import datetime,timezone
from pathlib import Path

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'src'))
from factory_state.dynamodb import DynamoDBStateStore
from factory_state.model import TaskState,FactoryStateMachine,OWNER_IDENTITY,StateError

TABLE='tims-software-factory-state'
FACTORY='tims-software-factory'
TASK='state-cas-canary-001'
MISSING='state-cas-missing-001'


def run(db,journal,now):
    store=DynamoDBStateStore(TABLE,db)
    if store.load_state(FACTORY,TASK) is not None or store.load_state(FACTORY,MISSING) is not None:
        raise StateError('Canary already exists or scope differs; no repeat')
    before=TaskState(FACTORY,TASK,'PAUSED',0,now,OWNER_IDENTITY)
    item={**store._serialize_state(before),'SK':{'S':'STATE'}}
    with journal.open('x',encoding='utf-8') as stream:
        json.dump({'status':'ATTEMPTED_NO_RETRY','task':TASK,'missing_task':MISSING},stream)
    db.put_item(TableName=TABLE,Item=item,ConditionExpression='attribute_not_exists(PK) AND attribute_not_exists(SK)')
    cases=(('missing',replace(before,task_id=MISSING)),
           ('payload',replace(before,updated_by='factory_controller_service')),
           ('state',replace(before,state='INTAKE')))
    for label,prior in cases:
        machine=FactoryStateMachine(prior)
        after=machine.owner_override(OWNER_IDENTITY,'PAUSED',expected_version=0,reason='Synthetic CAS rejection canary')
        try:
            store.persist_transition(prior,after,caller_identity=OWNER_IDENTITY,
                event_id='state-cas-'+label+'-001',audit_event=machine.last_audit_event)
        except Exception as error:
            response=getattr(error,'response',{})
            reasons=response.get('CancellationReasons',[])
            if (response.get('Error',{}).get('Code')!='TransactionCanceledException' or
                    not reasons or reasons[0].get('Code')!='ConditionalCheckFailed' or
                    any(r.get('Code') not in (None,'None') for r in reasons[1:])):
                raise StateError('Unexpected canary failure; reconcile without retry') from None
        else:
            raise StateError('Invalid state write unexpectedly succeeded; stop')
        event_key={'PK':{'S':f'FACTORY#{FACTORY}#TASK#{prior.task_id}'},
                   'SK':{'S':f'EVENT#{after.updated_at.isoformat()}#state-cas-{label}-001'}}
        if db.get_item(TableName=TABLE,Key=event_key,ConsistentRead=True).get('Item'):
            raise StateError('Rejected transaction left audit state')
        if store.load_state(FACTORY,TASK)!=before or store.load_state(FACTORY,MISSING) is not None:
            raise StateError('Rejected transaction changed state')
    machine=FactoryStateMachine(before)
    after=machine.owner_override(OWNER_IDENTITY,'PAUSED',expected_version=0,reason='Synthetic exact-state CAS canary complete; remains paused')
    store.persist_transition(before,after,caller_identity=OWNER_IDENTITY,
        event_id='state-cas-valid-001',audit_event=machine.last_audit_event)
    if store.load_state(FACTORY,TASK)!=after:raise StateError('Canary completion not verified')
    return {'status':'STATE_CAS_CANARY_VERIFIED','task_id':TASK,'state':after.state,'version':after.version,
        'missing_record_rejected':True,'changed_payload_rejected':True,'changed_state_rejected':True,
        'rejected_transactions_atomic':True,'exact_state_transition_verified':True,
        'pilot_state_modified':False,'model_calls':0,'budget_writes':0,'records_deleted':0,
        'finished_at':datetime.now(timezone.utc).isoformat()}


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--execute',action='store_true');p.add_argument('journal',type=Path)
    p.add_argument('result',type=Path);args=p.parse_args()
    if not args.execute or args.journal.exists() or args.result.exists():
        raise StateError('Explicit execution and new journal/result paths required')
    import boto3
    from botocore.config import Config
    config=Config(retries={'total_max_attempts':1},connect_timeout=5,read_timeout=10)
    session=boto3.Session(region_name='ca-central-1')
    identity=session.client('sts',config=config).get_caller_identity()
    if identity.get('Arn')!='arn:aws:iam::666730517561:root':
        raise StateError('Canary requires the existing authenticated Factory owner root session')
    result=run(session.client('dynamodb',config=config),args.journal,datetime.now(timezone.utc))
    with args.result.open('x',encoding='utf-8') as stream:json.dump(result,stream,indent=2)
    print(json.dumps(result))


if __name__=='__main__':main()
