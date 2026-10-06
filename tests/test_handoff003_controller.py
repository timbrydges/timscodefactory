from datetime import timedelta
import unittest
from factory_runtime.handoff003_attempts import key
from factory_runtime.handoff003_packets import TASK
from factory_runtime.handoff003_controller import decide
from factory_runtime.handoff003_receipts import sha
from factory_state.scope import canonical
from test_handoff003_receipts import HandoffReceiptTests,ROOT

class ControllerDecisionTests(unittest.TestCase):
    def setUp(self):
        self.f=HandoffReceiptTests();self.f.setUp()
        self.rows={role:{**key(role),'task_id':{'S':TASK},'role':{'S':role},
            'source_commit':{'S':'a'*40},'status':{'S':'COMPLETE'},'reservation_status':{'S':'HELD'},
            'reserved_micro_usd':{'N':'250000'},'actual_micro_usd':{'N':'100000'},
            'request_digest':{'S':self.f.requests[role]},'output_digest':{'S':sha(canonical(e))}}
            for role,e in self.f.chain.items()}
    def run_decision(self,count=3,**changes):
        roles=list(self.f.chain)[:count]
        args=dict(attempts={r:self.rows[r] if r in roles else None for r in self.rows},
            envelopes={r:self.f.chain[r] for r in roles},root=ROOT,trusted_keys=self.f.keys,
            source_commit='a'*40,candidate_commit='b'*40,
            request_digests={r:self.f.requests[r] for r in roles},now=self.f.now,
            verify_executed_tests=lambda commit,digest:True)
        return decide(**{**args,**changes})
    def test_ordered_prefix_never_grants_execution_authority(self):
        for count,next_role in enumerate(('builder','inspector','qa')):
            result=self.run_decision(count)
            self.assertEqual(result['next_role'],next_role)
            self.assertFalse(result['execution_authorized'])
            self.assertEqual(result['worker_invocations'],0)
        result=self.run_decision()
        self.assertEqual(result['status'],'COMPLETED_NO_DISPATCH')
        self.assertIsNone(result['next_role'])
    def test_uncertain_or_out_of_order_claim_stops(self):
        self.rows['builder']['status']['S']='STARTED'
        self.assertEqual(self.run_decision(1)['status'],'STOPPED_NO_RETRY')
        self.assertEqual(self.run_decision(0,attempts={'builder':None,'inspector':self.rows['inspector'],'qa':None})['status'],'STOPPED_NO_RETRY')
    def test_tampering_expiration_missing_reads_and_failed_tests_stop(self):
        for change in ({'attempts':{}},{'envelopes':{}},{'now':self.f.now+timedelta(hours=2)},
                       {'verify_executed_tests':lambda *_:False}):
            self.assertEqual(self.run_decision(**change)['status'],'STOPPED_NO_RETRY')
        self.rows['qa']['output_digest']['S']='sha256:'+'0'*64
        self.assertEqual(self.run_decision()['status'],'STOPPED_NO_RETRY')
