"""Optional emulator integration of actual signature verification and storage."""
import sys
import unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
try:
 import boto3
 from moto import mock_aws
except ImportError:
 mock_aws=None
from scripts.scope_dispatch_canary import run

@unittest.skipIf(mock_aws is None,'Optional moto[dynamodb] integration')
class SignedScopeCanaryTests(unittest.TestCase):
 def test_full_model_free_canary(self):
  with mock_aws():
   db=boto3.client('dynamodb',region_name='ca-central-1')
   db.create_table(TableName='state-table',KeySchema=[{'AttributeName':'PK','KeyType':'HASH'},{'AttributeName':'SK','KeyType':'RANGE'}],AttributeDefinitions=[{'AttributeName':'PK','AttributeType':'S'},{'AttributeName':'SK','AttributeType':'S'}],BillingMode='PAY_PER_REQUEST')
   result=run(db,'state-table','123-1','a'*40)
   self.assertEqual(result['conclusion'],'success')
   self.assertEqual(result['model_calls'],0)
   self.assertEqual(len(result['checks']),12)
