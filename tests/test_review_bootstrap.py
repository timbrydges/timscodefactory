from datetime import timedelta
import unittest
from unittest.mock import Mock, patch
from factory_runtime.review_bootstrap import run, TABLE, PARTITION, CLAIMS, FACTORY, TASK
from factory_runtime.worker import digest
from factory_state.model import StateError
from factory_state.scope import canonical
import test_review_material as materials
from test_review_provider_claims import boto3, Config, mock_aws


@unittest.skipIf(mock_aws is None,'Requires moto[dynamodb]')
class BootstrapTests(unittest.TestCase):
    def setUp(self):
        aws=mock_aws();aws.start();self.addCleanup(aws.stop)
        self.f=materials.MaterialTests();self.f.setUp();self.addCleanup(self.f.doCleanups)
        self.material=self.f.load();self.now=self.f.f.now
        self.db=boto3.client('dynamodb',region_name='ca-central-1',config=Config(retries={'total_max_attempts':1}))
        for table,keys in [(TABLE,['PK','SK']),(CLAIMS,['PK'])]:
            self.db.create_table(TableName=table,KeySchema=[{'AttributeName':k,'KeyType':'HASH' if k=='PK' else 'RANGE'} for k in keys],
                AttributeDefinitions=[{'AttributeName':k,'AttributeType':'S'} for k in keys],BillingMode='PAY_PER_REQUEST')
        self.sts=Mock(get_caller_identity=Mock(return_value={'Account':'666730517561','Arn':'arn:aws:iam::666730517561:root'}))
        self.config={'kind':'bounded_review001_paused_bootstrap','factory_id':FACTORY,'task_id':TASK,
            'source_commit':self.material.source_commit,'contract_digest':digest(self.material.contract_bytes),
            'owner_identity':'tim_brydges','initial_state':'PAUSED','provider_calls':0,
            'not_before':int(self.now.timestamp()),'expires_at':int(self.now.timestamp())+600,'nonce':'a'*32}

    def execute(self,**changes):
        kw={'approved_digest':digest(canonical(self.config)),'material':self.material,'db':self.db,
            'sts':self.sts,'clock':lambda:self.now,'enabled':True};kw.update(changes)
        return run(self.config,**kw)

    def test_atomic_paused_bootstrap_reconciles_without_new_write(self):
        self.assertEqual(self.execute()['status'],'PAUSED_BOOTSTRAP_VERIFIED')
        self.assertEqual(self.execute()['writes'],0)
        self.assertEqual(len(self.db.scan(TableName=TABLE)['Items']),3)
        self.assertEqual(self.db.scan(TableName=CLAIMS)['Items'],[])

    def test_any_existing_claim_blocks_all_state_writes(self):
        self.db.put_item(TableName=CLAIMS,Item={'PK':{'S':'BOUNDED_REVIEW#001#ROLE#qa'},'status':{'S':'STARTED'}})
        with self.assertRaises(StateError):self.execute()
        self.assertEqual(self.db.scan(TableName=TABLE)['Items'],[])

    def test_marker_prevents_resurrection_of_missing_state(self):
        self.execute()
        self.db.delete_item(TableName=TABLE,Key={'PK':{'S':PARTITION},'SK':{'S':'STATE'}})
        with self.assertRaises(StateError):self.execute()
        self.assertEqual(len(self.db.scan(TableName=TABLE)['Items']),2)

    def test_lost_transaction_response_reconciles_without_retry(self):
        original=self.db.transact_write_items
        def lost(**kw):original(**kw);raise TimeoutError('fixture lost response')
        with patch.object(self.db,'transact_write_items',side_effect=lost) as tx:
            self.assertEqual(self.execute()['status'],'PAUSED_BOOTSTRAP_VERIFIED');self.assertEqual(tx.call_count,1)

    def test_disabled_changed_approval_expiry_and_source_do_not_write(self):
        for kw in ({'enabled':False},{'approved_digest':digest(b'wrong')},
                   {'clock':lambda:self.now+timedelta(hours=1)}):
            with self.assertRaises(StateError):self.execute(**kw)
        self.config['initial_state']='IMPLEMENTATION'
        with self.assertRaises(StateError):self.execute()
        self.assertEqual(self.db.scan(TableName=TABLE)['Items'],[])
