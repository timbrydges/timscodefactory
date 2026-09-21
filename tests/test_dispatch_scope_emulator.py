"""Optional DynamoDB expression proof; not a live AWS verification."""
import sys
import unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
try:
 from moto import mock_aws
 import boto3
 from botocore.exceptions import ClientError
except ImportError:
 mock_aws = None
from test_dispatch_ledger import snapshot, REQUEST, NOW
from factory_state.dispatch import DynamoDBDispatchStore
from factory_state.dynamodb import DynamoDBStateStore
from factory_state.model import CONTROLLER_IDENTITY

def check():
 db=boto3.client('dynamodb',region_name='ca-central-1')
 db.create_table(TableName='state-table',KeySchema=[{'AttributeName':'PK','KeyType':'HASH'},{'AttributeName':'SK','KeyType':'RANGE'}],AttributeDefinitions=[{'AttributeName':'PK','AttributeType':'S'},{'AttributeName':'SK','AttributeType':'S'}],BillingMode='PAY_PER_REQUEST')
 state=snapshot(); store=DynamoDBDispatchStore('state-table',db)
 item=DynamoDBStateStore._serialize_state(state);item['SK']={'S':'STATE'}
 db.put_item(TableName='state-table',Item=item)
 def blocked(fn):
  try: fn()
  except ClientError as e:
   assert e.response['Error']['Code']=='TransactionCanceledException',e
  else: raise AssertionError('unauthorized dispatch succeeded')
 enqueue=lambda:store.enqueue(state,REQUEST,caller_identity=CONTROLLER_IDENTITY,now=NOW)
 claim=lambda:store.claim(state,REQUEST,worker_id='worker-1',caller_identity=CONTROLLER_IDENTITY,now=NOW)
 blocked(enqueue)
 cap={'PK':{'S':'FACTORY#factory#TASK#SCOPE#OBJECTIVE#factory-autonomy'},'SK':{'S':'CAPABILITY#durable-dispatch'},'status':{'S':'OPEN'},'owner_identity':{'S':'tim_brydges'},'contract_digest':{'S':REQUEST.contract_digest}}
 cap['expires_at']={'N':str(int(NOW.timestamp())+300)}
 db.put_item(TableName='state-table',Item=cap)
 blocked(enqueue)
 review={'PK':item['PK'],'SK':{'S':'SCOPE#lease-1'},'status':{'S':'ACCEPTED'},'binding':{'S':store._binding(REQUEST)},'reviewer_identity':{'S':'engineering_agent_service'},'review_evidence_digest':{'S':'sha256:'+'f'*64}}
 review['expires_at']={'N':str(int(NOW.timestamp())+300)}
 db.put_item(TableName='state-table',Item=review);blocked(enqueue)
 review['reviewer_identity']={'S':'independent_inspector_service'}
 db.put_item(TableName='state-table',Item=review);enqueue()
 cap['status']={'S':'COMPLETE'};db.put_item(TableName='state-table',Item=cap);blocked(claim)
 assert store.read(state,REQUEST)['status']=={'S':'READY'}
 cap['status']={'S':'OPEN'};db.put_item(TableName='state-table',Item=cap)
 claim();blocked(claim)

@unittest.skipIf(mock_aws is None, 'Optional local DynamoDB emulator: install moto[dynamodb]==5.1.12')
class DispatchScopeEmulatorTests(unittest.TestCase):
 def test_scope_conditions_and_duplicate_claim(self):
  with mock_aws():
   check()

