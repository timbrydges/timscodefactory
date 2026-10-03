import sys
import unittest
from datetime import timedelta
from pathlib import Path
from unittest.mock import Mock

ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'src'),str(ROOT/'tests')]
import test_pilot002_authorization as fixtures
from factory_runtime.pilot002_workflow import run_once
from factory_runtime.pilot002_attempts import Pilot002AttemptStore
from factory_runtime.pilot002_packets import builder_packet,review_packet,REVIEW_BINDINGS
from factory_state.model import StateError
from factory_state.scope import canonical


class WorkflowTests(unittest.TestCase):
    def setUp(self):
        self.auth=fixtures.AllowanceTests();self.auth.setUp();self.configure()

    def configure(self,role='builder'):
        payload,args=self.auth.context(role);self.envelope=self.auth.sign(payload)
        request=args.pop('request_bytes');now=args.pop('now');self.events=[];self.rows={}
        self.db=Mock()
        def claim(**kw):
            self.events.append('claim');pk=kw['Item']['PK']['S']
            if pk in self.rows:raise RuntimeError('already claimed')
            self.rows[pk]=kw['Item']
        self.db.put_item.side_effect=claim
        self.db.update_item.side_effect=lambda **kw:self.events.append('complete')
        self.adapter=Mock()
        self.adapter.build_request.side_effect=lambda packet:request
        self.adapter.send_once.side_effect=lambda **kw:(self.events.append('send') or b'provider fixture')
        packet=(builder_packet(ROOT) if role=='builder' else review_packet(ROOT,role=role,
            builder_response=args['builder_response'],candidate_commit=args['candidate_commit']))
        output=({'task_id':packet['task_id'],'packet_digest':packet['packet_digest'],
            'files':{'fingerprint.py':'# generated candidate\n','tests/test_fingerprint.py':'# generated tests\n'}}
            if role=='builder' else {**{k:packet[k] for k in REVIEW_BINDINGS},
                'verdict':'ACCEPTED','rationale':'Source-only review.','findings':[]})
        self.parsed={'model_id':packet['model_id'],'output_bytes':canonical(output),'actual_micro_usd':120}
        self.adapter.parse_response.side_effect=lambda raw,packet:self.parsed
        self.load=Mock(side_effect=lambda:(self.events.append('credential') or 'private-test-credential'))
        self.clock=Mock(return_value=now)
        self.args={**args,'store':Pilot002AttemptStore(self.db),'adapter':self.adapter,
            'load_credential':self.load,'clock':self.clock,'enabled':True}

    def run_workflow(self,**change):
        return run_once(self.envelope,**{**self.args,**change})

    def assert_no_send(self):
        self.adapter.send_once.assert_not_called();self.db.update_item.assert_not_called()

    def test_disabled_default_stops_before_any_dependency(self):
        args=dict(self.args);args.pop('enabled')
        with self.assertRaises(StateError):run_once(self.envelope,**args)
        self.adapter.build_request.assert_not_called();self.clock.assert_not_called()
        self.load.assert_not_called();self.db.put_item.assert_not_called()

    def test_claim_precedes_credentials_and_completion_retains_hold(self):
        result=self.run_workflow()
        self.assertEqual(self.events,['claim','credential','send','complete'])
        self.assertFalse(result['gate_authority']);self.assertFalse(result['output']['executed'])
        self.assertEqual(result['reservation_status'],'HELD')
        self.assertEqual(next(iter(self.rows.values()))['reserved_micro_usd'],{'N':'250000'})
        self.assertNotIn('private-test-credential',canonical(result).decode())

    def test_invalid_signature_cannot_claim_or_read_credential(self):
        self.envelope['signature']='A'*88
        with self.assertRaisesRegex(StateError,'authorization'):self.run_workflow()
        self.db.put_item.assert_not_called();self.load.assert_not_called();self.assert_no_send()

    def test_duplicate_invocation_cannot_send_again(self):
        self.run_workflow()
        with self.assertRaisesRegex(StateError,'reservation'):self.run_workflow()
        self.adapter.send_once.assert_called_once();self.load.assert_called_once()

    def test_uncertain_claim_stops_without_credentials(self):
        self.db.put_item.side_effect=TimeoutError('uncertain')
        with self.assertRaisesRegex(StateError,'reservation'):self.run_workflow()
        self.db.put_item.assert_called_once();self.load.assert_not_called();self.assert_no_send()

    def test_expiry_checked_after_claim_and_after_credential(self):
        now=self.auth.now;expired=now+timedelta(hours=2)
        for times,stage,loads in [([now,expired],'expiry_before_credential',0),
                                 ([now,now,expired],'expiry_before_provider',1),
                                 ([now,now,now-timedelta(seconds=1)],'expiry_before_provider',1)]:
            self.configure();self.clock.side_effect=times
            with self.subTest(stage=stage),self.assertRaisesRegex(StateError,stage):self.run_workflow()
            self.assertEqual(self.load.call_count,loads);self.assertEqual(len(self.rows),1);self.assert_no_send()

    def test_credential_failure_retains_claim_and_sanitizes_error(self):
        self.load.side_effect=RuntimeError('private-test-credential')
        with self.assertRaisesRegex(StateError,'credential') as caught:self.run_workflow()
        self.assertNotIn('private-test-credential',str(caught.exception));self.assertEqual(len(self.rows),1)
        self.assert_no_send()

    def test_provider_timeout_never_retries_or_completes(self):
        self.adapter.send_once.side_effect=TimeoutError('private-test-credential')
        with self.assertRaisesRegex(StateError,'provider'):self.run_workflow()
        self.adapter.send_once.assert_called_once();self.db.update_item.assert_not_called()
        self.assertEqual(len(self.rows),1)

    def test_wrong_model_over_quote_malformed_or_unbound_output_keeps_hold(self):
        for change in ({'model_id':'different-model'},{'actual_micro_usd':240001},
                       {'actual_micro_usd':True},{'output_bytes':b'{}'},
                       {'output_bytes':b'x'*32769}):
            self.configure();self.parsed.update(change)
            with self.subTest(change=change),self.assertRaisesRegex(StateError,'response'):self.run_workflow()
            self.adapter.send_once.assert_called_once();self.db.update_item.assert_not_called()

    def test_completion_uncertainty_does_not_resend(self):
        self.db.update_item.side_effect=TimeoutError('uncertain')
        with self.assertRaisesRegex(StateError,'completion'):self.run_workflow()
        self.adapter.send_once.assert_called_once();self.db.update_item.assert_called_once()
        self.assertEqual(len(self.rows),1)

    def test_both_review_roles_remain_unsigned_and_non_authoritative(self):
        for role in ('inspector','qa'):
            self.configure(role);result=self.run_workflow()
            self.assertEqual(result['role'],role);self.assertFalse(result['output']['gate_authority'])
            self.assertFalse(result['output']['tests_executed']);self.assertFalse(result['production_release_authorized'])

    def test_caller_mutation_cannot_expand_validated_cost_bound(self):
        def load():
            self.args['pricing']['maximum_cost_micro_usd']=250000
            return 'private-test-credential'
        self.load.side_effect=load;self.parsed['actual_micro_usd']=245000
        with self.assertRaisesRegex(StateError,'response'):self.run_workflow()
        self.db.update_item.assert_not_called()


if __name__=='__main__':unittest.main()
