from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import timedelta
import unittest

from factory_runtime.security_provider_claims import SecurityProviderClaims
from factory_runtime.security_provider_scope import CLAIM_KEY, validate_unsigned
from factory_runtime.review_provider_claims import TABLE
from factory_state.model import StateError
from test_security_provider_scope import fixture, NOW
from test_review_provider_claims import mock_aws


@unittest.skipIf(mock_aws is None, 'Requires moto[dynamodb]')
class SecurityClaimTests(unittest.TestCase):
    def setUp(self):
        import boto3
        from botocore.config import Config
        aws = mock_aws(); aws.start(); self.addCleanup(aws.stop)
        self.db = boto3.client('dynamodb', region_name='ca-central-1',
                              config=Config(retries={'total_max_attempts': 1}))
        self.db.create_table(TableName=TABLE, KeySchema=[{'AttributeName':'PK','KeyType':'HASH'}],
            AttributeDefinitions=[{'AttributeName':'PK','AttributeType':'S'}], BillingMode='PAY_PER_REQUEST')
        self.store = SecurityProviderClaims(self.db); self.dispatch = 'd'*64
        scope, price, ready, payload = fixture()
        self.grant = validate_unsigned(payload, scope=scope, pricing=price, readiness=ready, now=NOW)

    def row(self):
        return self.db.get_item(TableName=TABLE, Key={'PK':{'S':CLAIM_KEY}}, ConsistentRead=True)['Item']

    def test_complete_retains_hold_and_rejects_new_attempt(self):
        for _ in range(2): self.store.hold(self.grant, self.dispatch, now=NOW)
        self.store.begin_send(self.grant, self.dispatch, now=NOW)
        self.store.complete(self.grant, self.dispatch, now=NOW, output=b'review', actual_micro_usd=100)
        self.assertEqual(self.row()['status'], {'S':'COMPLETE'})
        self.assertEqual(self.row()['reservation_status'], {'S':'HELD'})
        self.assertEqual(self.row()['reserved_micro_usd'], {'N':'250000'})
        for method in (self.store.hold, self.store.begin_send):
            with self.assertRaises(StateError): method(self.grant, self.dispatch, now=NOW)

    def test_racing_and_restarted_sends_have_only_one_winner(self):
        self.store.hold(self.grant, self.dispatch, now=NOW)
        def send(_):
            try:
                SecurityProviderClaims(self.db).begin_send(self.grant, self.dispatch, now=NOW)
                return True
            except StateError: return False
        with ThreadPoolExecutor(max_workers=2) as pool:
            self.assertEqual(sorted(pool.map(send, range(2))), [False, True])
        self.assertFalse(send(None))

    def test_lost_write_response_and_overcap_cost_never_release_or_retry(self):
        self.store.hold(self.grant, self.dispatch, now=NOW)
        update = self.db.update_item
        def lost(**kwargs):
            update(**kwargs)
            raise TimeoutError('response lost')
        self.db.update_item = lost
        with self.assertRaises(StateError): self.store.begin_send(self.grant, self.dispatch, now=NOW)
        self.db.update_item = update
        with self.assertRaises(StateError): self.store.begin_send(self.grant, self.dispatch, now=NOW)
        for cost in (True, -1, self.grant.maximum_cost_micro_usd+1):
            with self.assertRaises(StateError):
                self.store.complete(self.grant, self.dispatch, now=NOW, output=b'review', actual_micro_usd=cost)
        self.assertEqual(self.row()['status'], {'S':'STARTED'})
        self.assertEqual(self.row()['reservation_status'], {'S':'HELD'})

    def test_historical_review_claims_unchanged(self):
        rows = [{'PK':{'S':f'BOUNDED_REVIEW#{run}#ROLE#{role}'}, 'status':{'S':'STARTED'},
                 'reservation_status':{'S':'HELD'}}
                for run in ('001','002','003','004') for role in ('builder','inspector','qa')]
        for row in rows: self.db.put_item(TableName=TABLE, Item=row)
        self.store.hold(self.grant, self.dispatch, now=NOW)
        self.store.begin_send(self.grant, self.dispatch, now=NOW)
        for row in rows:
            self.assertEqual(self.db.get_item(TableName=TABLE, Key={'PK':row['PK']})['Item'], row)

    def test_changed_or_expired_grant_cannot_consume_hold(self):
        self.store.hold(self.grant, self.dispatch, now=NOW)
        for grant in (replace(self.grant, maximum_cost_micro_usd=1),
                      replace(self.grant, scope_digest='sha256:'+'0'*64),
                      replace(self.grant, expires_at=int(NOW.timestamp()))):
            with self.assertRaises(StateError): self.store.begin_send(grant, self.dispatch, now=NOW)
        with self.assertRaises(StateError):
            self.store.begin_send(self.grant, self.dispatch, now=NOW+timedelta(hours=1))
        self.assertEqual(self.row()['status'], {'S':'RESERVED'})


if __name__ == '__main__': unittest.main()
