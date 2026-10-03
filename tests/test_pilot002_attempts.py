import copy
import sys
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import Mock

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT/'src'), str(ROOT/'scripts')]
from factory_runtime.pilot002_attempts import Pilot002AttemptStore, TABLE, ROLES, CAP_MICRO_USD, key
from factory_state.model import StateError
from prepare_pilot002_attempts import render, validate_changes, IAM_ROLES, STACK


class AttemptTests(unittest.TestCase):
    def setUp(self):
        self.now = datetime(2026, 10, 3, 17, tzinfo=timezone.utc)
        self.args = dict(role='builder', request_bytes=b'exact request', source_commit='a'*40,
            approval_digest='sha256:'+'b'*64, pricing_digest='sha256:'+'c'*64,
            now=self.now, approval_expires_at=self.now+timedelta(minutes=30),
            pricing_expires_at=self.now+timedelta(minutes=30))
        self.db = Mock(); self.store = Pilot002AttemptStore(self.db)
        self.rows = {}; self.lock = threading.Lock()
        def put(**kw):
            self.assertEqual(kw['TableName'], TABLE)
            self.assertEqual(kw['ConditionExpression'], 'attribute_not_exists(PK)')
            pk = kw['Item']['PK']['S']
            with self.lock:
                if pk in self.rows: raise RuntimeError('conditional failure')
                self.rows[pk] = copy.deepcopy(kw['Item'])
        self.db.put_item.side_effect = put

    def test_three_fixed_claims_bound_total_and_never_recycle(self):
        for role in ROLES:
            self.store.begin(**{**self.args, 'role': role})
            with self.assertRaises(StateError):
                self.store.begin(**{**self.args, 'role': role, 'request_bytes': b'new', 'source_commit': 'd'*40})
        self.assertEqual(len(self.rows), 3)
        self.assertEqual(sum(int(row['reserved_micro_usd']['N']) for row in self.rows.values()), 750000)
        self.assertTrue(all(row['reservation_status']['S']=='HELD' for row in self.rows.values()))

    def test_concurrent_claims_only_one_succeeds(self):
        barrier = threading.Barrier(2)
        def claim(_):
            barrier.wait()
            try: self.store.begin(**self.args); return True
            except StateError: return False
        with ThreadPoolExecutor(max_workers=2) as pool:
            self.assertEqual(sorted(pool.map(claim, range(2))), [False, True])
        self.assertEqual(len(self.rows), 1)

    def test_invalid_scope_and_windows_do_not_write(self):
        changes = [{'role':'security'}, {'role':[]}, {'request_bytes':b''},
            {'request_bytes':b'x'*65537}, {'source_commit':'main'}, {'approval_digest':'unbound'},
            {'pricing_digest':None}, {'now':self.now.replace(tzinfo=None)},
            {'approval_expires_at':self.now}, {'pricing_expires_at':self.now},
            {'approval_expires_at':self.now+timedelta(seconds=3601)}]
        for change in changes:
            with self.subTest(change=change), self.assertRaises(StateError):
                self.store.begin(**{**self.args, **change})
        self.db.put_item.assert_not_called()

    def test_unknown_write_never_retries(self):
        self.db.put_item.side_effect = TimeoutError('uncertain')
        with self.assertRaises(StateError): self.store.begin(**self.args)
        self.db.put_item.assert_called_once()
        self.db.get_item.assert_not_called()

    def test_completion_is_bound_and_retains_full_hold(self):
        digest = self.store.begin(**self.args)
        self.store.complete(role='builder', request_digest=digest, output_bytes=b'result', actual_micro_usd=120)
        call = self.db.update_item.call_args.kwargs
        self.assertEqual(call['Key'], key('builder'))
        self.assertIn('request_digest = :request', call['ConditionExpression'])
        self.assertIn('#s = :started', call['ConditionExpression'])
        self.assertEqual(call['ExpressionAttributeValues'][':cap'], {'N':str(CAP_MICRO_USD)})
        self.assertNotIn('reserved_micro_usd', call['UpdateExpression'])
        self.assertNotIn('reservation_status', call['UpdateExpression'])

    def test_invalid_completion_keeps_hold_and_does_not_update(self):
        digest = self.store.begin(**self.args)
        for amount in (-1, 250001, True, '1'):
            with self.assertRaises(StateError):
                self.store.complete(role='builder', request_digest=digest, output_bytes=b'result', actual_micro_usd=amount)
        self.db.update_item.assert_not_called()
        self.assertEqual(next(iter(self.rows.values()))['reservation_status'], {'S':'HELD'})

    def test_unknown_completion_never_retries(self):
        self.db.update_item.side_effect = TimeoutError('uncertain')
        with self.assertRaises(StateError):
            self.store.complete(role='qa', request_digest='sha256:'+'a'*64, output_bytes=b'x', actual_micro_usd=0)
        self.db.update_item.assert_called_once()


class TemplateTests(unittest.TestCase):
    def change(self):
        return {'Status':'CREATE_COMPLETE','ExecutionStatus':'AVAILABLE',
            'StackId':f'arn:aws:cloudformation:ca-central-1:666730517561:stack/{STACK}/test',
            'Changes':[{'Type':'Resource','ResourceChange':{'LogicalResourceId':k,
                'Action':'Add','ResourceType':v['Type']}} for k,v in render()['Resources'].items()]}

    def test_only_own_row_in_new_table_and_no_deletion_or_credentials(self):
        t = render(); r = t['Resources']; table = r['Attempts']
        self.assertEqual(table['DeletionPolicy'], 'Retain')
        self.assertEqual(table['UpdateReplacePolicy'], 'Retain')
        self.assertTrue(table['Properties']['DeletionProtectionEnabled'])
        self.assertNotIn('TimeToLiveSpecification', table['Properties'])
        self.assertEqual(table['Properties']['KeySchema'], [{'AttributeName':'PK','KeyType':'HASH'}])
        for role in ROLES:
            p = r[role.title()+'AttemptPolicy']['Properties']
            self.assertEqual(p['Roles'], [IAM_ROLES[role]])
            statement, = p['PolicyDocument']['Statement']
            self.assertEqual(statement['Action'], ['dynamodb:GetItem','dynamodb:PutItem','dynamodb:UpdateItem'])
            self.assertEqual(statement['Resource'], {'Fn::GetAtt':['Attempts','Arn']})
            self.assertEqual(statement['Condition']['ForAllValues:StringEquals']['dynamodb:LeadingKeys'], [key(role)['PK']['S']])
            self.assertEqual(statement['Condition']['Null'], {'dynamodb:LeadingKeys':'false'})
        validate_changes(t, self.change())

    def test_broader_policy_or_unexpected_cloud_changes_rejected(self):
        t = render(); t['Resources']['QaAttemptPolicy']['Properties']['Roles'].append('other')
        with self.assertRaises(StateError): validate_changes(t, self.change())
        for mutate in (lambda c:c['Changes'].pop(),
                       lambda c:c['Changes'][0]['ResourceChange'].update(Action='Modify'),
                       lambda c:c.update(NextToken='more'),
                       lambda c:c.update(StackId='wrong'),
                       lambda c:c.update(ExecutionStatus='EXECUTE_COMPLETE')):
            c=self.change(); mutate(c)
            with self.assertRaises(StateError): validate_changes(render(), c)


if __name__ == '__main__': unittest.main()
