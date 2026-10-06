import unittest
from unittest.mock import Mock
from factory_runtime import handoff003_qa_paid_recovery_canary as c
from factory_state.model import StateError

class Denied(Exception):
    def __init__(self,code):self.response={'Error':{'Code':code}}

class RecoveryCanaryTests(unittest.TestCase):
    def test_own_impossible_predicate_and_cross_scope_denials(self):
        db=Mock();db.put_item.side_effect=[Denied('ConditionalCheckFailedException'),Denied('AccessDeniedException'),Denied('AccessDeniedException'),Denied('AccessDeniedException')]
        self.assertEqual(len(c.probe(db)),4)
        for call in db.put_item.call_args_list:
            self.assertEqual(call.kwargs['ConditionExpression'],'attribute_exists(PK) AND attribute_not_exists(PK)')
    def test_unexpected_permission_or_acceptance_fails(self):
        for effect in (None,Denied('AccessDeniedException'),TimeoutError()):
            db=Mock();db.put_item.side_effect=effect
            with self.assertRaises(StateError):c.probe(db)
    def test_disabled_before_files_or_clients(self):
        with self.assertRaises(StateError):c.dispatch(None,None,root=None,env={})
