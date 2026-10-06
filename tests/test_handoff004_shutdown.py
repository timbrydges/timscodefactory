import copy
from types import SimpleNamespace
import unittest
from unittest.mock import Mock
from quiesce_handoff004 import quiesce,FUNCTIONS,NAME,policy
from factory_state.model import StateError


class ShutdownTests(unittest.TestCase):
    def setUp(self):
        meta=SimpleNamespace(config=SimpleNamespace(retries={'total_max_attempts':1}),region_name='ca-central-1')
        self.sts=SimpleNamespace(meta=meta,get_caller_identity=Mock(return_value={'Account':'666730517561'}))
        self.lam=SimpleNamespace(meta=meta,put_function_concurrency=Mock(),
            get_function_concurrency=Mock(return_value={'ReservedConcurrentExecutions':0}))
        self.document=policy({'qa':'arn:aws:lambda:ca-central-1:666730517561:function:tims-factory-handoff-004-qa:3'})
        def put(**kwargs):
            import json
            self.document=json.loads(kwargs['PolicyDocument'])
        self.iam=SimpleNamespace(meta=meta,get_role_policy=Mock(side_effect=lambda **_: {'PolicyDocument':copy.deepcopy(self.document)}),
            put_role_policy=Mock(side_effect=put))
        self.record=Mock()
    def run_shutdown(self):
        return quiesce(sts=self.sts,lam=self.lam,iam=self.iam,record=self.record)
    def test_repeatable_shutdown_removes_only_known_invoke_grant(self):
        for _ in range(2):
            result=self.run_shutdown()
            self.assertEqual(result['status'],'QUIESCED_NEW_INVOCATIONS_BLOCKED')
            self.assertFalse(result['running_invocations_cancelled'])
            self.assertEqual(result['ledger_writes'],0)
        self.assertEqual(self.iam.put_role_policy.call_count,1)
        self.assertEqual({c.kwargs['FunctionName'] for c in self.lam.put_function_concurrency.call_args_list},set(FUNCTIONS))
        self.assertTrue(all(c.kwargs['ReservedConcurrentExecutions']==0 for c in self.lam.put_function_concurrency.call_args_list))
    def test_one_failed_stop_does_not_skip_other_functions_or_policy(self):
        self.lam.put_function_concurrency.side_effect=[TimeoutError('private'),None,None,None]
        result=self.run_shutdown()
        self.assertEqual(result['status'],'SHUTDOWN_INCOMPLETE')
        self.assertEqual(self.lam.put_function_concurrency.call_count,4)
        self.iam.put_role_policy.assert_called_once()
        self.assertNotIn('private',str(result))
    def test_unknown_policy_is_not_replaced_but_all_functions_are_stopped(self):
        self.document['Statement'].append({'Effect':'Allow','Action':'s3:*','Resource':'*'})
        result=self.run_shutdown()
        self.assertEqual(result['status'],'SHUTDOWN_INCOMPLETE')
        self.iam.put_role_policy.assert_not_called()
        self.assertEqual(self.lam.put_function_concurrency.call_count,4)
    def test_failed_journal_does_not_prevent_shutdown_or_claim_success(self):
        self.record.side_effect=OSError('private')
        result=self.run_shutdown()
        self.assertEqual(result['status'],'SHUTDOWN_INCOMPLETE')
        self.assertEqual(self.lam.put_function_concurrency.call_count,4)
        self.iam.put_role_policy.assert_called_once()
    def test_failed_or_unreserved_readback_is_not_disabled(self):
        for response in ({},{'ReservedConcurrentExecutions':False},{'ReservedConcurrentExecutions':1}):
            self.lam.get_function_concurrency.return_value=response
            self.assertEqual(self.run_shutdown()['status'],'SHUTDOWN_INCOMPLETE')
    def test_wrong_account_or_retry_policy_blocks_changes(self):
        self.sts.get_caller_identity.return_value={'Account':'wrong'}
        with self.assertRaises(StateError):self.run_shutdown()
        self.sts.get_caller_identity.return_value={'Account':'666730517561'}
        self.lam.meta.config.retries={'total_max_attempts':2}
        with self.assertRaises(StateError):self.run_shutdown()
        self.lam.put_function_concurrency.assert_not_called()
        self.iam.put_role_policy.assert_not_called()

    def test_other_region_cannot_modify_similarly_named_functions(self):
        self.lam.meta.region_name='us-east-1'
        with self.assertRaises(StateError):self.run_shutdown()
        self.lam.put_function_concurrency.assert_not_called()
