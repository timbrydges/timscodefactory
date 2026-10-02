import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'src'),str(ROOT/'scripts')]
from factory_runtime.google_qa_boundary import FLAG, KEY, TABLE, GoogleQaAttemptStore, handler
from factory_state.model import StateError
from prepare_google_qa_broker import SECRET_ARN, render


class Table:
    def __init__(self): self.item=None
    def put_item(self, **kwargs):
        assert kwargs['TableName']==TABLE
        assert kwargs['ConditionExpression']=='attribute_not_exists(PK) AND attribute_not_exists(SK)'
        if self.item: raise RuntimeError('conditional failure')
        self.item=kwargs['Item']
    def update_item(self, **kwargs):
        assert kwargs['Key']==KEY and kwargs['TableName']==TABLE
        assert kwargs['ConditionExpression']=='#s=:started AND request_digest=:digest'
        if self.item['status']!={'S':'STARTED'} or self.item['request_digest']!=kwargs['ExpressionAttributeValues'][':digest']:
            raise RuntimeError('conditional failure')
        self.item['status']={'S':'COMPLETE'}


class GoogleBoundaryTests(unittest.TestCase):
    def args(self):
        return dict(request_bytes=b'bound request',approval_digest='sha256:'+'a'*64,source_commit='b'*40)

    def test_new_instances_and_changed_requests_cannot_repeat(self):
        table=Table()
        first=GoogleQaAttemptStore(TABLE,table)
        digest=first.begin(**self.args())
        for args in (self.args(), {**self.args(),'source_commit':'c'*40},
                     {**self.args(),'request_bytes':b'new request'}):
            with self.assertRaises(StateError): GoogleQaAttemptStore(TABLE,table).begin(**args)
        first.complete(request_digest=digest,response={'status':'UNAUTHENTICATED_PROVIDER_RESPONSE','gate_authority':False})
        with self.assertRaises(StateError): GoogleQaAttemptStore(TABLE,table).begin(**self.args())

    def test_unknown_write_never_returns_permission(self):
        client=Mock()
        client.put_item.side_effect=TimeoutError('PRIVATE upstream error')
        with self.assertRaises(StateError) as error: GoogleQaAttemptStore(TABLE,client).begin(**self.args())
        self.assertNotIn('PRIVATE',str(error.exception))
        self.assertEqual(client.put_item.call_count,1)
        client.get_item.assert_not_called()

    def test_wrong_table_or_binding_and_authority_rejected(self):
        with self.assertRaises(StateError): GoogleQaAttemptStore('tims-factory-acceptance-budget',Mock())
        client=Mock(); store=GoogleQaAttemptStore(TABLE,client)
        for change in ({'request_bytes':b'x'*32769},{'approval_digest':'invalid'},{'source_commit':True}):
            with self.assertRaises(StateError): store.begin(**{**self.args(),**change})
        with self.assertRaises(StateError):
            store.complete(request_digest='sha256:'+'a'*64,response={'status':'ACCEPTED','gate_authority':True})
        client.put_item.assert_not_called(); client.update_item.assert_not_called()

    def test_completion_conflict_is_not_a_retry(self):
        table=Table(); store=GoogleQaAttemptStore(TABLE,table); store.begin(**self.args())
        with self.assertRaises(StateError):
            store.complete(request_digest='sha256:'+'c'*64,response={'status':'UNAUTHENTICATED_PROVIDER_RESPONSE','gate_authority':False})
        self.assertEqual(table.item['status'],{'S':'STARTED'})

    def test_handler_has_no_live_branch_even_if_flag_is_enabled(self):
        with tempfile.TemporaryDirectory() as directory:
            (Path(directory)/'BUILD.json').write_text(json.dumps({'source_commit':'a'*40}))
            with patch.dict(os.environ,{'LAMBDA_TASK_ROOT':directory,FLAG:'false'},clear=True):
                event={'kind':'google_qa_broker_boundary_probe','source_commit':'a'*40}
                result=handler(event,None)
                self.assertEqual(result['secret_reads'],0); self.assertEqual(result['model_calls'],0)
                for changed in ({**event,'kind':'generate'},{**event,'source_commit':'b'*40},{**event,'extra':True}):
                    with self.assertRaises(StateError): handler(changed,None)
                os.environ[FLAG]='true'
                with self.assertRaises(StateError): handler(event,None)

    def test_template_has_only_exact_secret_ledger_logs_and_disabled_version(self):
        template=render(); r=template['Resources']; self.assertEqual(len(r),5)
        statements=r['Role']['Properties']['Policies'][0]['PolicyDocument']['Statement']
        self.assertEqual(statements[0]['Resource'],SECRET_ARN)
        self.assertEqual(statements[0]['Action'],['secretsmanager:GetSecretValue'])
        self.assertEqual(statements[1]['Resource'],{'Fn::GetAtt':['Attempts','Arn']})
        self.assertNotIn('dynamodb:DeleteItem',json.dumps(template))
        self.assertNotIn('kms:Sign',json.dumps(template))
        self.assertNotIn('AWS::Lambda::Permission',json.dumps(template))
        self.assertNotIn('TimeToLiveSpecification',r['Attempts']['Properties'])
        self.assertEqual(r['Attempts']['DeletionPolicy'],'Retain')
        self.assertEqual(r['Function']['Properties']['Environment']['Variables'][FLAG],'false')
        self.assertEqual(json.loads((ROOT/'infra/roles/google-qa-broker-disabled.cloudformation.json').read_bytes()),template)


if __name__=='__main__': unittest.main()
