from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import timedelta
import unittest
from factory_state.model import StateError
from factory_runtime.review_provider_claims import ReviewProviderClaims,TABLE
from factory_runtime.review_provider_scope import validate_unsigned
from test_review_provider_scope import fixture,NOW
try:
    import boto3
    from botocore.config import Config
    from moto import mock_aws
except ImportError:
    mock_aws=None


@unittest.skipIf(mock_aws is None,'Requires moto[dynamodb]')
class ClaimTests(unittest.TestCase):
    def setUp(self):
        aws=mock_aws();aws.start();self.addCleanup(aws.stop)
        self.db=boto3.client('dynamodb',region_name='ca-central-1',
                            config=Config(retries={'total_max_attempts':1}))
        self.db.create_table(TableName=TABLE,KeySchema=[{'AttributeName':'PK','KeyType':'HASH'}],
            AttributeDefinitions=[{'AttributeName':'PK','AttributeType':'S'}],BillingMode='PAY_PER_REQUEST')
        self.store=ReviewProviderClaims(self.db);self.dispatch='d'*64
        scope,price,ready,payload=fixture()
        # Internal shape for store tests only; signature verification has its own real-key tests.
        self.grant=validate_unsigned(payload,scope=scope,pricing=price,readiness=ready,now=NOW)

    def row(self):
        return self.db.get_item(TableName=TABLE,Key={'PK':{'S':'BOUNDED_REVIEW#004#ROLE#builder'}},
                                ConsistentRead=True)['Item']

    def test_shared_hold_then_one_send_and_completion_never_releases(self):
        for _ in range(2):self.assertEqual(self.store.hold(self.grant,self.dispatch,now=NOW),'RESERVED')
        self.store.begin_send(self.grant,self.dispatch,now=NOW)
        self.store.complete(self.grant,self.dispatch,now=NOW,output=b'result',actual_micro_usd=100)
        self.assertEqual(self.row()['status'],{'S':'COMPLETE'})
        self.assertEqual(self.row()['reserved_micro_usd'],{'N':'250000'})
        self.assertEqual(self.row()['reservation_status'],{'S':'HELD'})
        with self.assertRaises(StateError):self.store.hold(self.grant,self.dispatch,now=NOW)
        with self.assertRaises(StateError):self.store.begin_send(self.grant,self.dispatch,now=NOW)

    def test_successor_send_never_changes_historical_uncertain_hold(self):
        old={'PK':{'S':'BOUNDED_REVIEW#001#ROLE#builder'},'status':{'S':'STARTED'},
             'reservation_status':{'S':'HELD'},'reserved_micro_usd':{'N':'250000'}}
        self.db.put_item(TableName=TABLE,Item=old)
        old002={**old,'PK':{'S':'BOUNDED_REVIEW#002#ROLE#builder'}}
        self.db.put_item(TableName=TABLE,Item=old002)
        old003={**old,'PK':{'S':'BOUNDED_REVIEW#003#ROLE#builder'}}
        self.db.put_item(TableName=TABLE,Item=old003)
        self.store.hold(self.grant,self.dispatch,now=NOW)
        self.store.begin_send(self.grant,self.dispatch,now=NOW)
        self.assertEqual(self.row()['task_id'],{'S':'bounded-review-004'})
        self.assertEqual(self.db.get_item(TableName=TABLE,Key={'PK':old['PK']})['Item'],old)
        self.assertEqual(self.db.get_item(TableName=TABLE,Key={'PK':old002['PK']})['Item'],old002)
        self.assertEqual(self.db.get_item(TableName=TABLE,Key={'PK':old003['PK']})['Item'],old003)

    def test_concurrent_send_claim_and_restarted_process_allow_one_winner(self):
        self.store.hold(self.grant,self.dispatch,now=NOW)
        def attempt(_):
            try:ReviewProviderClaims(self.db).begin_send(self.grant,self.dispatch,now=NOW);return 'claimed'
            except StateError:return 'blocked'
        with ThreadPoolExecutor(max_workers=2) as pool:results=list(pool.map(attempt,range(2)))
        self.assertEqual(sorted(results),['blocked','claimed'])
        self.assertEqual(attempt(None),'blocked')
        self.assertEqual(self.row()['status'],{'S':'STARTED'})

    def test_exactly_three_fixed_holds_total_the_existing_run_reservation(self):
        for role in ('builder','inspector','qa'):
            scope,price,ready,payload=fixture(role)
            grant=validate_unsigned(payload,scope=scope,pricing=price,readiness=ready,now=NOW)
            self.store.hold(grant,self.dispatch,now=NOW)
        items=self.db.scan(TableName=TABLE)['Items']
        self.assertEqual(len(items),3)
        self.assertEqual({v['role']['S']:int(v['reserved_micro_usd']['N']) for v in items},
                         {'builder':250000,'inspector':175000,'qa':75000})
        self.assertEqual(sum(int(item['reserved_micro_usd']['N']) for item in items),500000)
        with self.assertRaises(StateError):self.store.hold(replace(self.grant,role='fourth'),self.dispatch,now=NOW)

    def test_changed_scope_dispatch_or_expiry_cannot_reclaim_hold(self):
        self.store.hold(self.grant,self.dispatch,now=NOW)
        for grant,dispatch in ((replace(self.grant,scope_digest='sha256:'+'0'*64),self.dispatch),
                (self.grant,'e'*64),(replace(self.grant,maximum_cost_micro_usd=1),self.dispatch)):
            with self.assertRaises(StateError):self.store.hold(grant,dispatch,now=NOW)
            with self.assertRaises(StateError):self.store.begin_send(grant,dispatch,now=NOW)
        with self.assertRaises(StateError):self.store.begin_send(self.grant,self.dispatch,now=NOW+timedelta(hours=1))
        self.assertEqual(self.row()['status'],{'S':'RESERVED'})

    def test_uncertain_write_and_over_bound_cost_keep_permanent_hold(self):
        self.store.hold(self.grant,self.dispatch,now=NOW)
        original=self.db.update_item
        def lost_response(**kwargs):original(**kwargs);raise TimeoutError('lost response')
        self.db.update_item=lost_response
        with self.assertRaises(StateError):self.store.begin_send(self.grant,self.dispatch,now=NOW)
        self.db.update_item=original
        with self.assertRaises(StateError):self.store.begin_send(self.grant,self.dispatch,now=NOW)
        with self.assertRaises(StateError):self.store.complete(self.grant,self.dispatch,now=NOW,
            output=b'result',actual_micro_usd=self.grant.maximum_cost_micro_usd+1)
        self.assertEqual(self.row()['status'],{'S':'STARTED'})
