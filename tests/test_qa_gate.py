import base64
import copy
import json
import os
import sys
import tempfile
import unittest
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import Mock, patch

ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'src'),str(ROOT/'scripts')]
from factory_runtime import qa_gate as gate, qa_gate_runtime as runtime
from factory_state.dynamodb import DynamoDBStateStore
from factory_state.model import StateError
from factory_state.signers import public_key_der
from scope_dispatch_canary import fixture_keys, sign
from test_progression import MemoryStates


class CheckedStates(MemoryStates):
    def persist_transition(self,before,after,**kwargs):
        DynamoDBStateStore._validate_audit_event(before,after,kwargs['caller_identity'],kwargs['audit_event'])
        DynamoDBStateStore._validate_state_delta(before,after,kwargs['caller_identity'],kwargs['audit_event'])
        super().persist_transition(before,after,**kwargs)


class QaGateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.facts=gate.evidence(ROOT)
        cls.before=gate.baseline(ROOT)

    def setUp(self):
        self.directory=tempfile.TemporaryDirectory(); self.addCleanup(self.directory.cleanup)
        self.root=Path(self.directory.name)
        for name in (gate.REGISTRY,gate.BASELINE):
            p=self.root/name; p.parent.mkdir(parents=True,exist_ok=True); p.write_bytes((ROOT/name).read_bytes())
        self.commit='a'*40
        (self.root/'BUILD.json').write_text(json.dumps({'source_commit':self.commit}))
        self.now=datetime(2026,10,3,8,30,tzinfo=timezone.utc)
        self.config={'authorization_id':gate.AUTHORIZATION,'owner_identity':'tim_brydges','approved':True,
            'source_commit':self.commit,'not_before':int(self.now.timestamp()),
            'expires_at':int(self.now.timestamp())+600,'nonce':'b'*32,'recorded_google_evidence_accepted':True}
        self.states=CheckedStates(self.before)
        self.keys,self.private=fixture_keys(self.root,(gate.IDENTITY,))
        self.addCleanup(patch.stopall)
        patch.object(gate,'evidence',return_value=self.facts).start()
        patch.object(gate,'load_trusted_signers',return_value=self.keys).start()
        patch.object(runtime,'load_trusted_signers',return_value=self.keys).start()
        self.env={gate.ENABLED:'true',gate.CONFIG:json.dumps(self.config),
            'FACTORY_REVIEW_ROLE':'qa','FACTORY_REVIEW_KEY_ARN':gate.KEY,'FACTORY_OPERATIONAL_EXECUTION_ENABLED':'false'}
        self.event={'kind':'publish_qa_gate','source_commit':self.commit,
                    'authorization_id':gate.AUTHORIZATION,'nonce':self.config['nonce']}
        self.kms=Mock(); self.sts=Mock()
        self.sts.get_caller_identity.return_value={'Account':'666730517561',
            'Arn':'arn:aws:sts::666730517561:assumed-role/tims-factory-review-qa/test'}
        self.kms.get_public_key.return_value={'KeyId':gate.KEY,'KeyUsage':'SIGN_VERIFY',
            'KeySpec':'ECC_NIST_EDWARDS25519','SigningAlgorithms':[runtime.ALGORITHM],
            'PublicKey':public_key_der(self.keys[gate.IDENTITY])}
        self.kms.sign.side_effect=lambda **kw: {'KeyId':gate.KEY,'SigningAlgorithm':runtime.ALGORITHM,
            'Signature':sign(json.loads(kw['Message']),self.private[gate.IDENTITY],self.root)}

    def service(self):
        return gate.QaGateController(self.root,self.states,json.dumps(self.config),
                                    commit=self.commit,clock=lambda:self.now)

    def result(self,**changes):
        payload={**gate.payload_for(self.facts,self.config,issued_at=int(self.now.timestamp())),**changes}
        return {'payload':payload,'signature_base64':base64.b64encode(sign(payload,self.private[gate.IDENTITY],self.root)).decode()}

    def publish(self,clock=None):
        return runtime.publish(self.event,root=self.root,env=self.env,kms=self.kms,sts=self.sts,clock=clock or (lambda:self.now))

    def test_fresh_lease_independent_signature_and_controller_advance_once(self):
        service=self.service()
        self.assertEqual(service.issue_lease()['status'],'LEASE_ISSUED')
        result=self.publish()
        self.assertEqual(service.complete(result)['status'],'ADVANCED')
        self.assertEqual(service.complete(result)['status'],'ALREADY_ADVANCED')
        self.assertEqual((self.states.state.state,self.states.state.version),('SECURITY_REVIEW',14))
        self.assertEqual(self.states.state.leases[:-1],self.before.leases)
        self.assertTrue(all(x.revoked for x in self.states.state.leases))
        self.assertEqual(len(self.states.state.consumed_evidence_ids-self.before.consumed_evidence_ids),1)
        self.assertEqual([x[2]['audit_event']['event_type'] for x in self.states.writes],['LEASE_ISSUED','STATE_TRANSITION'])
        self.kms.sign.assert_called_once()
        self.assertLessEqual(len(self.kms.sign.call_args.kwargs['Message']),4096)
        self.assertFalse(result['payload']['production_release_authorized'])

    def test_valid_signature_without_lease_cannot_advance(self):
        with self.assertRaises(StateError): self.service().complete(self.result())
        self.assertEqual(self.states.writes,[])

    def test_changed_task_or_history_cannot_be_reset(self):
        for changed in (replace(self.before,version=13),replace(self.before,state='SECURITY_REVIEW'),
                        replace(self.before,leases=self.before.leases[:-1])):
            self.states.state=changed
            with self.assertRaises(StateError): self.service().issue_lease()
            with self.assertRaises(StateError): self.service().complete(self.result())
        self.assertEqual(self.states.writes,[])

    def test_changed_candidate_nonce_lease_target_or_evidence_rejects_even_signed(self):
        self.service().issue_lease()
        for changes in ({'candidate_commit':'f'*40},{'nonce':'c'*32},{'lease_id':'other'},
                        {'target_state':'RELEASE_READY'},{'executor_report_digest':'sha256:'+'0'*64},
                        {'google_evidence_type':'AUTHENTICATED_PROVIDER_RESPONSE'},{'verdict':'REJECTED'}):
            with self.subTest(changes=changes),self.assertRaises(StateError):
                self.service().complete(self.result(**changes))
        self.assertEqual(len(self.states.writes),1)

    def test_fake_or_mutated_signature_cannot_advance(self):
        self.service().issue_lease()
        result=self.result(); result['signature_base64']=base64.b64encode(b'x'*64).decode()
        with self.assertRaises(StateError): self.service().complete(result)
        self.assertEqual(len(self.states.writes),1)

    def test_signature_must_follow_lease_even_within_the_same_second(self):
        result=self.result()
        self.now+=timedelta(microseconds=1)
        self.service().issue_lease()
        with self.assertRaises(StateError): self.service().complete(result)
        self.assertEqual(len(self.states.writes),1)

    def test_unknown_write_outcome_reconciles_without_repeating_committed_transition(self):
        for operation in ('lease','complete'):
            self.states=CheckedStates(self.before); service=self.service()
            if operation=='complete': service.issue_lease()
            original=self.states.persist_transition
            def unknown(*a,**kw): original(*a,**kw); raise TimeoutError('unknown')
            self.states.persist_transition=unknown
            action=service.issue_lease if operation=='lease' else lambda:service.complete(self.result())
            with self.assertRaises(TimeoutError): action()
            count=len(self.states.writes); self.states.persist_transition=original
            self.assertIn(action()['status'],('LEASE_ALREADY_ISSUED','ALREADY_ADVANCED'))
            self.assertEqual(len(self.states.writes),count)

    def test_expired_unapproved_or_expanded_config_never_writes(self):
        original=copy.deepcopy(self.config)
        for changes in ({'approved':False},{'recorded_google_evidence_accepted':False},
            {'expires_at':original['not_before']},{'expires_at':original['not_before']+3601},
            {'not_before':True},{'nonce':'bad'},{'source_commit':'c'*40},{'extra':True}):
            self.config={**original,**changes}
            with self.subTest(changes=changes),self.assertRaises(StateError): self.service().issue_lease()
        self.assertEqual(self.states.writes,[])

    def test_expired_enrollment_or_signature_prevents_completion(self):
        self.service().issue_lease(); result=self.result()
        self.now+=timedelta(seconds=600)
        with self.assertRaises(StateError): self.service().complete(result)
        self.now-=timedelta(seconds=600)
        with patch.object(gate,'load_trusted_signers',return_value={}):
            with self.assertRaises(StateError): self.service().complete(result)
        self.assertEqual(len(self.states.writes),1)

    def test_disabled_handlers_reject_before_files_or_cloud_clients(self):
        with patch.dict(os.environ,{},clear=True),patch.object(Path,'read_bytes') as read:
            for handler in (runtime.signer_handler,runtime.controller_handler):
                with self.assertRaises(StateError): handler({},None)
            read.assert_not_called()

    def test_wrong_cloud_role_key_event_or_flag_never_signs(self):
        self.sts.get_caller_identity.return_value['Arn']='wrong'
        with self.assertRaises(StateError): self.publish()
        self.sts.get_caller_identity.return_value['Arn']='arn:aws:sts::666730517561:assumed-role/tims-factory-review-qa/test'
        self.kms.get_public_key.return_value['KeyId']='wrong'
        with self.assertRaises(StateError): self.publish()
        for changes in ({gate.ENABLED:'false'},{'FACTORY_REVIEW_ROLE':'security'},
                        {'FACTORY_OPERATIONAL_EXECUTION_ENABLED':'true'}):
            with patch.dict(self.env,changes),self.assertRaises(StateError): self.publish()
        self.kms.sign.assert_not_called()

    def test_expiry_during_preparation_and_signing_error_never_retry(self):
        clock=Mock(side_effect=[self.now,self.now+timedelta(seconds=600)])
        with self.assertRaises(StateError): self.publish(clock)
        self.kms.sign.assert_not_called()
        self.kms.sign.side_effect=TimeoutError('sensitive details')
        with self.assertRaisesRegex(StateError,'uncertain.*never retry'): self.publish()
        self.kms.sign.assert_called_once()


class QaGatePinnedEvidenceTests(unittest.TestCase):
    def test_live_signed_report_verifies_only_as_historical_provenance(self):
        facts=gate.evidence(ROOT)
        self.assertEqual(facts['google_evidence_type'],'OWNER_ACCEPTED_RECORDED_UNSIGNED_RESPONSE')
        self.assertNotIn('gate_authority',facts)
        self.assertEqual(gate.baseline(ROOT).version,12)

    def test_modified_provenance_rejected_before_publication(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            from factory_runtime.review_preparation import PACKET,REVIEW,BOOTSTRAP
            for name in (PACKET,REVIEW,BOOTSTRAP,gate.ATTESTATION,gate.REGISTRY,gate.BUNDLE,gate.PROOF):
                p=root/name; p.parent.mkdir(parents=True,exist_ok=True); p.write_bytes((ROOT/name).read_bytes())
            for name in (gate.ATTESTATION,gate.BUNDLE,gate.PROOF):
                p=root/name; raw=p.read_bytes(); p.write_bytes(raw+b' ')
                with self.assertRaises(StateError): gate.evidence(root)
                p.write_bytes(raw)


if __name__=='__main__': unittest.main()
