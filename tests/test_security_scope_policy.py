"""Real owner signatures; QA callback mocked here, separately integration-tested."""
from dataclasses import replace
from datetime import timedelta
import tempfile
import unittest
from unittest.mock import Mock, patch

import test_security_material as fixtures
from factory_runtime.intake import IntakePlan
from factory_runtime.security_qa_provenance import ConsumedQAProvenance
from factory_runtime.security_scope_policy import SecurityScopeReview, IDENTITY, EVIDENCE, STOP, RATIONALE
from factory_state.dispatch import DynamoDBDispatchStore
from factory_state.model import TaskState, Lease, StateError, CONTROLLER_IDENTITY
from scripts.scope_dispatch_canary import fixture_keys, sign


class SecurityScopeTests(unittest.TestCase):
    def setUp(self):
        f=fixtures.SecurityMaterialTests();f.setUp();self.addCleanup(f.doCleanups)
        self.f=f;self.now=f.f.f.now;m=f.load();q=m.binding.qa;r=m.prepared().scope.request
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.keys,self.private=fixture_keys(self.temp.name,('tim_brydges',IDENTITY))
        state=TaskState(q.factory_id,q.task_id,'SECURITY_REVIEW',7,self.now,CONTROLLER_IDENTITY)
        self.states=Mock(load_state=Mock(return_value=state))
        prerequisite=ConsumedQAProvenance(binding=m.binding,qa_binding=f.qa,
            qa_request=f.f.load().prepared('qa').scope.request,states=self.states,ledger=Mock(),
            historical_key_loader=lambda _:self.keys,clock=lambda:self.now,contract_bytes=m.contract_bytes)
        times={'issued_at':int(self.now.timestamp()),'expires_at':int(self.now.timestamp())+600}
        cap={'kind':'capability','factory_id':q.factory_id,'objective_id':r.objective_id,
            'capability_id':r.capability_id,'contract_digest':r.contract_digest,
            'owner_identity':'tim_brydges','required_evidence':EVIDENCE,'stop_condition':STOP,**times}
        review={'kind':'scope_review','factory_id':q.factory_id,'task_id':q.task_id,
            'binding':DynamoDBDispatchStore._binding(r),'verdict':'ACCEPTED',
            'reviewer_identity':IDENTITY,'rationale':RATIONALE,**times}
        plan=IntakePlan(q.factory_id,q.task_id,'SECURITY_REVIEW',7,
            Lease(r.lease_id,'deep_security_reviewer','deep_security_reviewer_service',
                  self.now+timedelta(minutes=15)),r,cap,review)
        self.args=dict(material=m,plan=plan,owner_signature=sign(cap,self.private['tim_brydges'],self.temp.name),
            prerequisites=prerequisite,key_loader=lambda _:self.keys,clock=lambda:self.now)

    def test_exact_scope_checks_owner_and_prerequisite(self):
        with patch.object(ConsumedQAProvenance,'__call__',return_value=True) as verify:
            self.assertEqual(SecurityScopeReview(**self.args).review(now=self.now),self.args['plan'].review_payload)
            verify.assert_called_once_with(self.args['material'].binding)

    def test_missing_qa_or_revoked_owner_blocks_review(self):
        with patch.object(ConsumedQAProvenance,'__call__',return_value=False):
            with self.assertRaises(StateError):SecurityScopeReview(**self.args).review(now=self.now)
        self.keys.pop('tim_brydges')
        with patch.object(ConsumedQAProvenance,'__call__',return_value=True) as verify:
            with self.assertRaises(StateError):SecurityScopeReview(**self.args).review(now=self.now)
            verify.assert_not_called()

    def test_owner_signed_expanded_stop_and_self_review_rejected(self):
        for change in ('stop','reviewer','lease'):
            p=self.args['plan']
            if change=='stop':p=replace(p,capability_payload={**p.capability_payload,'stop_condition':'release'})
            if change=='reviewer':p=replace(p,review_payload={**p.review_payload,'reviewer_identity':'deep_security_reviewer_service'})
            if change=='lease':p=replace(p,lease=replace(p.lease,expires_at=self.now+timedelta(hours=1)))
            args={**self.args,'plan':p,'owner_signature':sign(p.capability_payload,self.private['tim_brydges'],self.temp.name)}
            with patch.object(ConsumedQAProvenance,'__call__',return_value=True):
                with self.subTest(change=change),self.assertRaises(StateError):
                    SecurityScopeReview(**args).review(now=self.now)

    def test_stale_proof_version_and_receipt_lifetime_rejected(self):
        original=self.states.load_state.return_value
        for change in ('proof','version','receipt'):
            self.states.load_state.return_value=original
            args=dict(self.args)
            if change=='proof':args['clock']=lambda:self.now+timedelta(hours=2)
            if change=='version':self.states.load_state.return_value=replace(original,version=8)
            if change=='receipt':
                p=args['plan'];cap={**p.capability_payload,'expires_at':int(self.now.timestamp())+601}
                args['plan']=replace(p,capability_payload=cap)
                args['owner_signature']=sign(cap,self.private['tim_brydges'],self.temp.name)
            with patch.object(ConsumedQAProvenance,'__call__',return_value=True):
                with self.subTest(change=change),self.assertRaises(StateError):
                    SecurityScopeReview(**args).review(now=self.now)


if __name__ == '__main__':unittest.main()
