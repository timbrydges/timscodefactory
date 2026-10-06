"""Bounded, redacted observations of Pilot 002; never authorization or execution."""
import re
from datetime import datetime, timezone

from factory_state.dynamodb import DynamoDBStateStore
from factory_state.model import StateError
from .pilot002_bootstrap import FACTORY, TASK, TABLE as STATE_TABLE
from .pilot002_attempts import TABLE, key

ACCOUNT='666730517561'
REGION='ca-central-1'
WORKERS={role:('tims-factory-pilot-002-'+role,'FACTORY_PILOT002_EXECUTION_ENABLED')
         for role in ('builder','inspector','qa')}
ATTEMPTS={role:(TABLE,key(role)) for role in WORKERS}
for role,number in (('inspector','001'),('qa','001'),('qa','002'),('qa','003')):
    name=role+'_recovery'+number
    WORKERS[name]=(f'tims-factory-{role}-recovery-{number}',f'FACTORY_{role.upper()}_RECOVERY{number}_ENABLED')
    ATTEMPTS[name]=(f'tims-factory-{role}-recovery-{number}-attempts',
                   {'PK':{'S':f'RECOVERY#{number}#TASK#{TASK}#ROLE#{role}'}})


# Fixed inventory only: callers cannot expand observation to arbitrary resources.
for number in ('001', '002'):
    for role in ('builder', 'inspector', 'qa'):
        name = 'handoff'+number+'_'+role
        WORKERS[name] = (f'tims-factory-handoff-{number}-{role}', f'FACTORY_HANDOFF{number}_ENABLED')
        ATTEMPTS[name] = (f'tims-factory-handoff-{number}-attempts',
            {'PK': {'S': f'HANDOFF#{number}#TASK#authenticated-handoff-{number}#ROLE#{role}'}})


def _amount(item,field):
    value=item.get(field,{}).get('N')
    if type(value) is not str or not re.fullmatch(r'0|[1-9][0-9]{0,11}',value):
        raise StateError('Invalid monetary observation')
    return int(value)


def observe(*,sts,lam,db,clock=lambda:datetime.now(timezone.utc)):
    """Clients are operator-owned. Reads are sequential, not an atomic snapshot."""
    if sts.get_caller_identity().get('Account')!=ACCOUNT:
        raise StateError('Operator status requires the fixed Factory account')
    started=clock()
    if not isinstance(started,datetime) or started.tzinfo is None:
        raise StateError('Operator status requires an aware clock')
    workers={};attempts={};errors=[]
    for name,(function,flag) in WORKERS.items():
        try:
            config=lam.get_function_configuration(FunctionName=function)
            concurrent=lam.get_function_concurrency(FunctionName=function).get('ReservedConcurrentExecutions')
            enabled=config.get('Environment',{}).get('Variables',{}).get(flag)
            arn=f'arn:aws:lambda:{REGION}:{ACCOUNT}:function:{function}'
            if config.get('FunctionArn')!=arn or enabled not in ('true','false'):
                raise StateError('Worker identity or flag unavailable')
            if concurrent is not None and (type(concurrent) is not int or concurrent<0):
                raise StateError('Worker concurrency invalid')
            workers[name]={'status':'OBSERVED','execution_flag':enabled=='true',
                'reserved_concurrency':concurrent,
                'disabled_observed':enabled=='false' and type(concurrent) is int and concurrent==0}
        except Exception:
            workers[name]={'status':'UNKNOWN','disabled_observed':False}
            errors.append('worker:'+name)
    for name,(table,rowkey) in ATTEMPTS.items():
        try:
            item=db.get_item(TableName=table,Key=rowkey,ConsistentRead=True).get('Item')
            if not item:
                attempts[name]={'status':'ABSENT','attempt_reusable':False}
                continue
            status=item['status']['S'];hold=item['reservation_status']['S']
            if item.get('PK')!=rowkey['PK'] or status not in ('STARTED','COMPLETE') or hold!='HELD':
                raise StateError('Attempt observation differs')
            attempts[name]={'status':status,'reservation_status':hold,
                'reserved_micro_usd':_amount(item,'reserved_micro_usd'),
                'reported_actual_micro_usd':_amount(item,'actual_micro_usd') if 'actual_micro_usd' in item else None,
                'attempt_reusable':False}
        except Exception:
            attempts[name]={'status':'UNKNOWN','attempt_reusable':False}
            errors.append('attempt:'+name)
    try:
        state=DynamoDBStateStore(STATE_TABLE,db).load_state(FACTORY,TASK)
        task={'status':'OBSERVED','state':state.state,'version':state.version,
              'active_leases':sum(lease.active_at(started) for lease in state.leases)}
    except Exception:
        task={'status':'UNKNOWN'};errors.append('task')
    finished=clock()
    if not isinstance(finished,datetime) or finished.tzinfo is None or finished<started:
        raise StateError('Operator observation clock invalid')
    return {'status':'INCOMPLETE' if errors else 'OBSERVED','task_id':TASK,
        'started_at':started.isoformat(),'finished_at':finished.isoformat(),
        'task':task,'workers':workers,'attempts':attempts,'unavailable':errors,
        'all_workers_disabled_observed':all(w['disabled_observed'] for w in workers.values()),
        'known_reserved_micro_usd':sum(a.get('reserved_micro_usd',0) for a in attempts.values()),
        'reservation_total_complete':all(a['status']!='UNKNOWN' for a in attempts.values()),
        'known_reported_actual_micro_usd':sum(a.get('reported_actual_micro_usd') or 0 for a in attempts.values()),
        'invoice_verified':False,'gate_authority':False,'execution_authorized':False,
        'scope':'Pilot 002 and handoff 001/002 workers and attempts; authoritative task is Pilot 002 only; not all Factory infrastructure or IAM permissions'}
