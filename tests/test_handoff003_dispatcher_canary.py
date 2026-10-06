import unittest
from unittest.mock import Mock,patch
from botocore.exceptions import ClientError
from factory_runtime.handoff003_dispatcher_canary import probe,handler
from factory_state.model import StateError


class DispatcherCanaryTests(unittest.TestCase):
    def setUp(self):
        self.db=Mock();self.db.get_item.return_value={}
        def reject(**kw):
            code='AccessDeniedException' if kw['Item']['PK']['S']=='UNAUTHORIZED_DISPATCH_PROBE' else 'ConditionalCheckFailedException'
            raise ClientError({'Error':{'Code':code}},'PutItem')
        self.db.put_item.side_effect=reject
    def test_impossible_conditions_and_cross_scope_denial(self):
        self.assertEqual(probe(self.db)['state_writes'],0)
        self.assertEqual(self.db.put_item.call_count,4)
        for call in self.db.put_item.call_args_list:
            self.assertEqual(call.kwargs['ConditionExpression'],'attribute_exists(PK) AND attribute_not_exists(PK)')
    def test_freshness_and_wrong_permission_fail_closed(self):
        self.db.get_item.return_value={'Item':{'PK':{'S':'consumed'}}}
        with self.assertRaises(StateError):probe(self.db)
        self.db.put_item.assert_not_called()
        self.db.get_item.return_value={};self.db.put_item.side_effect=ClientError({'Error':{'Code':'AccessDeniedException'}},'PutItem')
        with self.assertRaises(StateError):probe(self.db)
    def test_disabled_mode_before_sdk_or_files(self):
        with patch.dict('os.environ',{},clear=True),patch('boto3.Session') as session:
            with self.assertRaises(StateError):handler(None,None)
            session.assert_not_called()
