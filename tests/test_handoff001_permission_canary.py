import unittest
from unittest.mock import Mock,patch
from botocore.exceptions import ClientError
from factory_runtime.handoff001_permission_canary import probe,dispatch
from factory_state.model import StateError


class HandoffPermissionCanaryTests(unittest.TestCase):
    def test_every_database_request_has_an_impossible_write_condition(self):
        db=Mock()
        def put(**args):
            self.assertEqual(args['ConditionExpression'],'attribute_exists(PK) AND attribute_not_exists(PK)')
            self.assertEqual(set(args['Item']),{'PK'})
            own=args['Item']['PK']['S'].endswith('#builder')
            raise ClientError({'Error':{'Code':'ConditionalCheckFailedException' if own else 'AccessDeniedException'}},'PutItem')
        db.put_item.side_effect=put
        self.assertEqual(len(probe(db,'builder')),3)

    def test_wrong_own_permission_or_unexpected_success_stops(self):
        db=Mock()
        with self.assertRaises(StateError):probe(db,'builder')
        db.put_item.side_effect=ClientError({'Error':{'Code':'AccessDeniedException'}},'PutItem')
        with self.assertRaises(StateError):probe(db,'builder')

    def test_live_or_unversioned_runtime_rejected_before_client(self):
        for enabled in ('true','false'):
            with patch('factory_runtime.handoff001_permission_canary._aws_session') as session:
                with self.assertRaises(StateError):dispatch({},Mock(invoked_function_arn=''),
                    env={'FACTORY_HANDOFF001_ENABLED':enabled},root=None)
                session.assert_not_called()
