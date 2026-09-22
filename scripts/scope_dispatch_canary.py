"""Model-free signature + DynamoDB dispatch canary in isolated task partitions.

Ephemeral fixture keys prove verification mechanics, not independent agent review.
No provider call, project activation, production deployment or deletion occurs.
"""
from __future__ import annotations
import hashlib
import json
import re
import subprocess
import sys
import tempfile
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from factory_state.dispatch import DispatchRequest, DynamoDBDispatchStore
from factory_state.dynamodb import DynamoDBStateStore
from factory_state.model import CONTROLLER_IDENTITY, Lease, TaskState, StateError
from factory_state.scope import SignedScopeStore, canonical

class DynamoFailure(RuntimeError):
    pass

class AwsCliDynamoDB:
    def __getattr__(self, method):
        if method not in {'put_item', 'get_item', 'update_item', 'transact_write_items'}:
            raise AttributeError(method)
        def call(**request):
            result = subprocess.run(['aws', 'dynamodb', method.replace('_', '-'), '--region', 'ca-central-1',
                '--cli-input-json', json.dumps(request), '--output', 'json'], capture_output=True, timeout=30)
            if result.returncode:
                # Expected conditional failures only; other AWS errors must fail the canary.
                if b'ConditionalCheckFailed' in result.stderr:
                    raise DynamoFailure('conditional rejection')
                raise RuntimeError('unexpected AWS CLI failure: ' + result.stderr.decode()[:1000])
            return json.loads(result.stdout or b'{}')
        return call

def fixture_keys(directory, identities=('tim_brydges', 'independent_inspector_service')):
    keys, private = {}, {}
    for identity in identities:
        key = Path(directory)/identity
        subprocess.run(['openssl', 'genpkey', '-algorithm', 'ED25519', '-out', str(key)], check=True, capture_output=True)
        keys[identity] = subprocess.check_output(['openssl', 'pkey', '-in', str(key), '-pubout'], stderr=subprocess.DEVNULL)
        private[identity] = key
    return keys, private

def sign(payload, key, directory):
    path = Path(directory)/'message'
    path.write_bytes(canonical(payload))
    return subprocess.check_output(['openssl', 'pkeyutl', '-sign', '-rawin', '-inkey', str(key), '-in', str(path)], stderr=subprocess.DEVNULL)

def run(client, table, run_id, commit, *, now=None):
    if not re.fullmatch(r'[0-9]+-[0-9]+', run_id) or not re.fullmatch(r'[a-f0-9]{40}', commit):
        raise ValueError('canary requires exact workflow run identity and commit')
    now = now or datetime.now(timezone.utc)
    task = 'scope-canary-' + run_id
    state = TaskState('tims-software-factory', task, 'IMPLEMENTATION', 1, now, CONTROLLER_IDENTITY,
        (Lease('fixture-builder', 'engineering_agent', 'engineering_agent_service', now+timedelta(minutes=10)),))
    request = DispatchRequest('fixture-builder', task, 'scope-enforcement', commit,
        'sha256:'+hashlib.sha256(b'Factory scope canary; synthetic only').hexdigest(),
        'sha256:'+hashlib.sha256(task.encode()).hexdigest())
    initial = DynamoDBStateStore._serialize_state(state);initial['SK']={'S':'STATE'}
    client.put_item(TableName=table, Item=initial, ConditionExpression='attribute_not_exists(PK) AND attribute_not_exists(SK)')
    ledger = DynamoDBDispatchStore(table, client)
    checks = []
    def reject(name, action):
        try: action()
        except Exception as error:
            conditional = isinstance(error, (DynamoFailure, StateError)) or (
                getattr(error, 'response', {}).get('Error', {}).get('Code') in
                {'ConditionalCheckFailedException', 'TransactionCanceledException'})
            if not conditional: raise
            checks.append(name)
        else: raise AssertionError(name+' unexpectedly succeeded')
    enqueue=lambda:ledger.enqueue(state,request,caller_identity=CONTROLLER_IDENTITY,now=now)
    claim=lambda:ledger.claim(state,request,caller_identity=CONTROLLER_IDENTITY,worker_id='fixture-worker',now=now)
    with tempfile.TemporaryDirectory(prefix='scope-canary-') as directory:
        keys, private = fixture_keys(directory)
        writer = SignedScopeStore(table, client, keys)
        times={'issued_at':int(now.timestamp()), 'expires_at':int(now.timestamp())+600}
        capability={'kind':'capability','factory_id':state.factory_id,'objective_id':task,
            'capability_id':request.capability_id,'contract_digest':request.contract_digest,
            'owner_identity':'tim_brydges','required_evidence':'Model-free rejection checks pass',
            'stop_condition':'Stop after this isolated canary',**times}
        owner_signature=sign(capability,private['tim_brydges'],directory)
        reject('missing_scope_denied',enqueue)
        reject('tampered_owner_receipt_denied',lambda:writer.approve_capability(state,request,
            {**capability,'required_evidence':'tampered'},owner_signature,now=now))
        writer.approve_capability(state,request,capability,owner_signature,now=now)
        reject('owner_receipt_replay_denied',lambda:writer.approve_capability(state,request,capability,owner_signature,now=now))
        reject('missing_independent_review_denied',enqueue)
        review={'kind':'scope_review','factory_id':state.factory_id,'task_id':task,
            'binding':ledger._binding(request),'verdict':'ACCEPTED',
            'reviewer_identity':'independent_inspector_service',
            'rationale':'Synthetic mechanics fixture; not a real independent review',**times}
        reject('wrong_signer_denied',lambda:writer.approve_task(state,request,review,
            sign(review,private['tim_brydges'],directory),now=now))
        writer.approve_task(state,request,review,sign(review,private['independent_inspector_service'],directory),now=now)
        enqueue(); checks.append('verified_records_allow_enqueue')
        capkey={'PK':{'S':f'FACTORY#{state.factory_id}#TASK#SCOPE#OBJECTIVE#{task}'},'SK':{'S':'CAPABILITY#scope-enforcement'}}
        def status(value):
            client.update_item(TableName=table,Key=capkey,UpdateExpression='SET #s=:s',
                ExpressionAttributeNames={'#s':'status'},ExpressionAttributeValues={':s':{'S':value}})
        status('COMPLETE');reject('completed_capability_blocks_queued_claim',claim)
        # Fixture reset solely to exercise the remaining isolated claim checks.
        status('OPEN')
        expired = {**review, 'expires_at':int(now.timestamp())-1}
        reject('expired_signed_review_denied',lambda:writer.approve_task(state,request,expired,
            sign(expired,private['independent_inspector_service'],directory),now=now))
        claim();checks.append('verified_records_allow_claim')
        reject('duplicate_claim_denied',claim)
        receipt='sha256:'+hashlib.sha256(b'fixture complete').hexdigest()
        ledger.record_receipt(state,request,worker_id='fixture-worker',receipt_digest=receipt,caller_identity=CONTROLLER_IDENTITY)
        ledger.record_receipt(state,request,worker_id='fixture-worker',receipt_digest=receipt,caller_identity=CONTROLLER_IDENTITY)
        assert ledger.read(state,request)['status']=={'S':'RECEIPT_RECORDED'}
        checks.append('receipt_retry_idempotent')
        status('COMPLETE')
        paused=replace(state,state='PAUSED',version=2,leases=(replace(state.leases[0],revoked=True),))
        item=DynamoDBStateStore._serialize_state(paused);item['SK']={'S':'STATE'}
        client.put_item(TableName=table,Item=item,ConditionExpression='#v=:old',
            ExpressionAttributeNames={'#v':'version'},ExpressionAttributeValues={':old':{'N':'1'}})
        checks.append('fixture_closed_and_paused')
    return {'schema_version':'1.0','source_commit':commit,'run_id':run_id,'task_id':task,
        'conclusion':'success','checks':checks,'model_calls':0,'production_deployments':0,
        'synthetic_signers':True,'independent_review_proven':False,'worker_activated':False}

if __name__ == '__main__':
    result=run(AwsCliDynamoDB(),'tims-software-factory-state',sys.argv[1],sys.argv[2])
    print(json.dumps(result,indent=2))
