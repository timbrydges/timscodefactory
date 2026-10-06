"""Model-free review persistence canary using two fixed synthetic task partitions."""
import argparse
from dataclasses import asdict
from datetime import datetime,timedelta,timezone
import hashlib
import json
from pathlib import Path
import re
import sys
import tempfile

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'src'))
sys.path.insert(0,str(ROOT))
from factory_runtime.progression import SignedResultProgressor
from factory_runtime.review_verdict import ReviewBinding,BoundReviewValidator,PinnedPythonTestEvidence
from factory_runtime.worker import digest
from factory_state.dispatch import DispatchRequest,DynamoDBDispatchStore
from factory_state.dynamodb import DynamoDBStateStore
from factory_state.model import TaskState,Lease,StateError,CONTROLLER_IDENTITY
from factory_state.scope import SignedScopeStore,canonical
from scripts.scope_dispatch_canary import fixture_keys,sign

TABLE='tims-software-factory-state'
FACTORY='tims-software-factory'
CASES=(('review-inspector-canary-001','independent_inspector','INSPECTION','QA'),
       ('review-qa-canary-001','qa_engineer','QA','SECURITY_REVIEW'))


def run(db,commit,journal,*,now=None):
    if not re.fullmatch('[0-9a-f]{40}',commit):raise StateError('Exact source required')
    now=now or datetime.now(timezone.utc)
    states=DynamoDBStateStore(TABLE,db);ledger=DynamoDBDispatchStore(TABLE,db)
    if any(states.load_state(FACTORY,task) is not None for task,_,_,_ in CASES):
        raise StateError('Canary partition already exists; reconcile without retry')
    # Exclusive journal precedes every cloud mutation; synthetic records are retained.
    with journal.open('x',encoding='utf-8') as stream:
        stream.write(json.dumps({'status':'ATTEMPTED_NO_RETRY','source_commit':commit,
            'tasks':[c[0] for c in CASES],'synthetic_signers':True})+'\n')
    results=[]
    with tempfile.TemporaryDirectory(prefix='review-canary-') as directory:
        keys,private=fixture_keys(directory,('tim_brydges','product_spec_reviewer_service',
            'independent_inspector_service','qa_engineer_service'))
        for task,role,stage,target in CASES:
            identity=role+'_service'
            lease=Lease('fixture-review',role,identity,now+timedelta(minutes=10))
            state=TaskState(FACTORY,task,stage,0,now,CONTROLLER_IDENTITY,(lease,))
            request=DispatchRequest(lease.lease_id,task,'synthetic-review-progression',commit,
                digest(b'Synthetic mechanics only; no real review authority'),digest(task.encode()))
            times={'issued_at':int(now.timestamp()),'expires_at':int(now.timestamp())+600}
            files={'fixture.py':'# synthetic fixture; not executed\n'}
            proof=canonical({'source_commit':commit,'candidate_commit':commit,'observed_at':now.isoformat(),
                'runtime':'python3.12-linux','python_version':'3.12.0','exit_code':0,
                'credentials_in_environment':False,'stdout':'','stderr':'Ran 1 tests in 0.001s\n\nOK\n',
                'files':{p:hashlib.sha256(v.encode()).hexdigest() for p,v in files.items()}})
            binding=ReviewBinding(FACTORY,task,role,commit,request.contract_digest,request.input_digest,
                commit,digest(canonical(files)),digest(proof),tuple(files))
            tests=PinnedPythonTestEvidence(binding,proof,files,test_count=1,clock=lambda:now)
            value={k:v for k,v in asdict(binding).items() if k!='allowed_paths'}
            value.update(kind='factory_review_v1',verdict='ACCEPTED',rationale='Synthetic fixture only',findings=[])
            output=canonical(value)
            item={**states._serialize_state(state),'SK':{'S':'STATE'}}
            db.transact_write_items(TransactItems=[{'Put':{'TableName':TABLE,'Item':record,
                'ConditionExpression':'attribute_not_exists(PK) AND attribute_not_exists(SK)'}}
                for record in (item,states._serialize_lease(state,lease))])
            scope=SignedScopeStore(TABLE,db,keys)
            cap={'kind':'capability','factory_id':FACTORY,'objective_id':task,
                'capability_id':request.capability_id,'contract_digest':request.contract_digest,
                'owner_identity':'tim_brydges','required_evidence':'Synthetic persistence canary',
                'stop_condition':'One transition and replay check only',**times}
            review={'kind':'scope_review','factory_id':FACTORY,'task_id':task,
                'binding':ledger._binding(request),'verdict':'ACCEPTED',
                'reviewer_identity':'product_spec_reviewer_service','rationale':'Synthetic fixture, not independent review',**times}
            scope.approve_capability(state,request,cap,sign(cap,private['tim_brydges'],directory),now=now)
            scope.approve_task(state,request,review,sign(review,private['product_spec_reviewer_service'],directory),now=now)
            dispatch_id=ledger.enqueue(state,request,caller_identity=CONTROLLER_IDENTITY,now=now)
            ledger.claim(state,request,caller_identity=CONTROLLER_IDENTITY,worker_id='fixture-review',now=now)
            payload={'kind':'role_result','factory_id':FACTORY,'task_id':task,
                'binding':ledger._binding(request),'dispatch_id':dispatch_id,'producer_identity':identity,
                'output_digest':digest(output),**times}
            ledger.record_signed_result(state,request,worker_id='fixture-review',payload=payload,
                signature=sign(payload,private[identity],directory),output=output)
            progressor=SignedResultProgressor(states,ledger,key_loader=lambda _:keys,clock=lambda:now,
                review_validator=BoundReviewValidator(binding,lambda *_:False))
            try:progressor.advance(FACTORY,task,request)
            except StateError:pass
            else:raise StateError('Missing independent tests unexpectedly accepted')
            if states.load_state(FACTORY,task)!=state:raise StateError('Rejected review changed state')
            progressor.review_validator=BoundReviewValidator(binding,tests)
            result=progressor.advance(FACTORY,task,request)
            after=states.load_state(FACTORY,task)
            if result['state']!=target or after.version!=1 or any(l.active_at(now) for l in after.leases):
                raise StateError('Unexpected persisted review transition')
            if progressor.advance(FACTORY,task,request)['status']!='ALREADY_ADVANCED' or states.load_state(FACTORY,task)!=after:
                raise StateError('Receipt replay changed state')
            results.append({'task':task,'state':target,'version':1,'missing_tests_rejected':True,'replay_idempotent':True})
    return {'status':'SYNTHETIC_REVIEW_PROGRESSION_VERIFIED','source_commit':commit,'results':results,
        'model_calls':0,'budget_writes':0,'production_deployments':0,'synthetic_signers':True,
        'independent_review_proven':False,'real_tests_proven':False,'worker_activated':False}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--execute',action='store_true');parser.add_argument('commit')
    parser.add_argument('journal',type=Path);parser.add_argument('result',type=Path)
    args=parser.parse_args()
    if not args.execute or args.journal.exists() or args.result.exists():raise StateError('Explicit execution and new paths required')
    import boto3
    from botocore.config import Config
    config=Config(retries={'total_max_attempts':1},connect_timeout=5,read_timeout=10)
    session=boto3.Session(region_name='ca-central-1')
    if session.client('sts',config=config).get_caller_identity()['Account']!='666730517561':raise StateError('Wrong account')
    result=run(session.client('dynamodb',config=config),args.commit,args.journal)
    with args.result.open('x',encoding='utf-8') as stream:json.dump(result,stream,indent=2)
    print(json.dumps(result))


if __name__=='__main__':main()
