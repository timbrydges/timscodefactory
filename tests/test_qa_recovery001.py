import copy
import json
import sys
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime,timedelta,timezone
from pathlib import Path
from unittest.mock import Mock

ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'src'),str(ROOT/'scripts')]
from factory_runtime import qa_recovery001 as p
from factory_state.model import StateError
import prepare_qa_recovery001_ledger as preview


class RecoveryTests(unittest.TestCase):
    def setUp(self):
        now=datetime(2026,10,4,12,tzinfo=timezone.utc)
        self.args=dict(candidate_commit=p.CANDIDATE,source_commit='a'*40,request_bytes=__import__('factory_runtime.pilot002_protocols',fromlist=['request_bytes']).request_bytes(ROOT,role='qa',builder_response=(ROOT/'tests/pilot002_reviewer_builder_context.json').read_bytes(),candidate_commit=p.CANDIDATE),
            approval_digest='sha256:'+'b'*64,pricing_digest='sha256:'+'c'*64,maximum_cost_micro_usd=0,
            now=now,approval_expires_at=now+timedelta(minutes=5),pricing_expires_at=now+timedelta(minutes=5))
        self.db=Mock();self.store=p.RecoveryAttemptStore(self.db,root=ROOT,enabled=True)
        self.rows={};self.lock=threading.Lock()
        def put(**kw):
            self.assertEqual(kw['TableName'],p.TABLE)
            self.assertEqual(kw['Item']['PK'],{'S':p.PK})
            self.assertEqual(kw['ConditionExpression'],'attribute_not_exists(PK)')
            with self.lock:
                if p.PK in self.rows:raise RuntimeError('conditional failure')
                self.rows[p.PK]=copy.deepcopy(kw['Item'])
        self.db.put_item.side_effect=put

    def test_disabled_default_has_no_writes(self):
        store=p.RecoveryAttemptStore(self.db,root=ROOT)
        with self.assertRaises(StateError):store.begin(**self.args)
        with self.assertRaises(StateError):store.complete(request_digest='',approval_digest='',output_bytes=b'',actual_micro_usd=0)
        self.assertEqual(self.db.mock_calls,[])

    def test_concurrent_claims_create_one_permanent_hold(self):
        barrier=threading.Barrier(2)
        def claim(_):
            barrier.wait()
            try:self.store.begin(**self.args);return True
            except StateError:return False
        with ThreadPoolExecutor(max_workers=2) as pool:
            self.assertEqual(sorted(pool.map(claim,range(2))),[False,True])
        self.assertEqual(len(self.rows),1)
        row=self.rows[p.PK];self.assertEqual(row['reserved_micro_usd'],{'N':'250000'})
        self.assertNotIn('ttl',row)
        changed={**self.args,'request_bytes':b'changed','approval_digest':'sha256:'+'d'*64,
            'now':self.args['now']+timedelta(days=1),'approval_expires_at':self.args['now']+timedelta(days=1,minutes=20),
            'pricing_expires_at':self.args['now']+timedelta(days=1,minutes=20)}
        with self.assertRaises(StateError):self.store.begin(**changed)
        self.assertEqual(self.rows[p.PK],row)
        self.assertNotEqual(p.TABLE,'tims-factory-pilot-002-attempts')
        self.assertNotEqual(p.PK,'PILOT#002#TASK#safe-workspace-fingerprint-001#ROLE#qa')

    def test_invalid_scope_cost_or_freshness_never_claims(self):
        for change in ({'candidate_commit':'d'*40},{'source_commit':'main'},{'maximum_cost_micro_usd':True},
                       {'maximum_cost_micro_usd':250001},{'maximum_cost_micro_usd':1},
                       {'request_bytes':b'x'*65537},{'approval_digest':'unbound'},
                       {'now':self.args['now'].replace(tzinfo=None)},
                       {'pricing_expires_at':self.args['now']},
                       {'pricing_expires_at':self.args['now']+timedelta(seconds=301)},
                       {'approval_expires_at':self.args['now']+timedelta(seconds=3601)}):
            with self.subTest(change=change),self.assertRaises(StateError):self.store.begin(**{**self.args,**change})
        self.db.put_item.assert_not_called()

    def test_uncertain_claim_is_not_retried_or_queried(self):
        self.db.put_item.side_effect=TimeoutError('sensitive detail')
        with self.assertRaises(StateError) as caught:self.store.begin(**self.args)
        self.assertNotIn('sensitive detail',str(caught.exception))
        self.db.put_item.assert_called_once();self.db.get_item.assert_not_called()

    def test_completion_is_bound_to_approval_quote_and_permanent_hold(self):
        request=self.store.begin(**self.args)
        self.store.complete(request_digest=request,approval_digest=self.args['approval_digest'],output_bytes=b'accepted fixture',actual_micro_usd=0)
        call=self.db.update_item.call_args.kwargs
        self.assertEqual(call['TableName'],p.TABLE);self.assertEqual(call['Key'],{'PK':{'S':p.PK}})
        for binding in ('approval_digest = :approval','request_digest = :request','maximum_cost_micro_usd >= :actual','scope_digest = :scope'):
            self.assertIn(binding,call['ConditionExpression'])
        self.assertNotIn('reservation_status',call['UpdateExpression'])
        self.assertNotIn('reserved_micro_usd',call['UpdateExpression'])
        self.db.update_item.side_effect=TimeoutError('sensitive detail')
        with self.assertRaises(StateError):self.store.complete(request_digest=request,approval_digest=self.args['approval_digest'],output_bytes=b'fixture',actual_micro_usd=0)
        self.assertEqual(self.db.update_item.call_count,2)
        self.db.put_item.assert_called_once()

    def test_modified_scope_is_rejected_before_any_client_use(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);path=root/p.SCOPE_FILE;path.parent.mkdir(parents=True)
            doc=json.loads((ROOT/p.SCOPE_FILE).read_bytes());doc['proposal']['maximum_provider_calls']=2
            path.write_text(json.dumps(doc))
            with self.assertRaises(StateError):p.RecoveryAttemptStore(self.db,root=root,enabled=True)
        self.assertEqual(self.db.mock_calls,[])

    def test_table_preview_has_no_runtime_access_or_old_table_changes(self):
        template=preview.render()
        changes={'Status':'CREATE_COMPLETE','ExecutionStatus':'AVAILABLE',
            'StackId':'arn:aws:cloudformation:ca-central-1:666730517561:stack/'+preview.STACK+'/fixture',
            'Changes':[{'Type':'Resource','ResourceChange':{'LogicalResourceId':'RecoveryAttempt','ResourceType':'AWS::DynamoDB::Table','Action':'Add'}}]}
        self.assertEqual(preview.validate_changes(template,changes)['iam_grants'],0)
        resource=template['Resources']['RecoveryAttempt']
        self.assertEqual(resource['DeletionPolicy'],'Retain')
        self.assertTrue(resource['Properties']['DeletionProtectionEnabled'])
        self.assertNotIn('TimeToLiveSpecification',resource['Properties'])
        for mutate in (lambda c:c.update(NextToken='more'),lambda c:c['Changes'].append(copy.deepcopy(c['Changes'][0])),
                       lambda c:c['Changes'][0]['ResourceChange'].update(Action='Modify')):
            changed=copy.deepcopy(changes);mutate(changed)
            with self.assertRaises(StateError):preview.validate_changes(template,changed)
        modified=copy.deepcopy(template);modified['Resources']['RecoveryAttempt']['Properties']['TableName']='tims-factory-pilot-002-attempts'
        with self.assertRaises(StateError):preview.validate_changes(modified,changes)


if __name__=='__main__':unittest.main()
