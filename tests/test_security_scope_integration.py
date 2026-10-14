"""Real QA/owner/reviewer signatures; storage and AWS custody are simulated."""
import base64
from dataclasses import replace
from datetime import timedelta
import unittest
from unittest.mock import Mock

import test_security_scope_policy as fixtures
import test_security_scope_signer as signer_fixture
from factory_runtime.security_qa_provenance import ConsumedQAProvenance
from factory_runtime.security_scope_policy import SecurityScopeReview, SecurityScopeSigner
from factory_runtime.worker import digest
from factory_state.dispatch import DynamoDBDispatchStore
from factory_state.model import Lease, StateError
from factory_state.scope import canonical
from scripts.scope_dispatch_canary import fixture_keys, sign


class SignedQAScopeTests(unittest.TestCase):
    get_caller_identity=signer_fixture.SecuritySignerTests.get_caller_identity
    get_public_key=signer_fixture.SecuritySignerTests.get_public_key
    sign=signer_fixture.SecuritySignerTests.sign

    def setUp(self):
        f=fixtures.SecurityScopeTests();f.setUp();self.addCleanup(f.doCleanups)
        self.f=f;self.calls=0;self.fail=False;self.on_key=lambda:None
        keys,private=fixture_keys(f.temp.name,('qa_engineer_service',))
        f.keys.update(keys);f.private.update(private)
        previous=f.args['prerequisites'];q=previous.qa_binding;r=previous.request
        output={k:getattr(q,k) for k in q.__dataclass_fields__ if k!='allowed_paths'}
        output.update(kind='factory_review_v1',verdict='ACCEPTED',rationale='Signed historical fixture.',findings=[])
        raw=canonical(output)
        payload={'kind':'role_result','factory_id':q.factory_id,'task_id':q.task_id,
            'binding':DynamoDBDispatchStore._binding(r),'dispatch_id':'d'*64,
            'producer_identity':'qa_engineer_service','output_digest':digest(raw),
            'issued_at':int(f.now.timestamp())-7200,'expires_at':int(f.now.timestamp())-6900}
        receipt_digest=digest(canonical(payload))
        material=f.f.load(qa_result_digest=receipt_digest)
        state=replace(f.states.load_state.return_value,
            leases=(Lease(r.lease_id,'qa_engineer','qa_engineer_service',f.now-timedelta(hours=1)),),
            consumed_evidence_ids=frozenset({'result-'+receipt_digest[7:]}))
        f.states.load_state.return_value=state
        self.row={'status':{'S':'RECEIPT_RECORDED'},'dispatch_id':{'S':'d'*64},
            'receipt_digest':{'S':receipt_digest},'result_payload':{'S':canonical(payload).decode()},
            'result_output':{'S':base64.b64encode(raw).decode()},
            'result_signature':{'S':base64.b64encode(sign(payload,private['qa_engineer_service'],f.temp.name)).decode()}}
        ledger=Mock(read=Mock(return_value=self.row),_binding=DynamoDBDispatchStore._binding)
        prerequisite=ConsumedQAProvenance(binding=material.binding,qa_binding=q,qa_request=r,
            states=f.states,ledger=ledger,historical_key_loader=lambda _:f.keys,
            clock=lambda:f.now,contract_bytes=material.contract_bytes)
        request=material.prepared().scope.request;p=f.args['plan']
        cap={**p.capability_payload,'contract_digest':request.contract_digest}
        review={**p.review_payload,'binding':DynamoDBDispatchStore._binding(request)}
        plan=replace(p,request=request,capability_payload=cap,review_payload=review)
        self.policy=SecurityScopeReview(material=material,plan=plan,
            owner_signature=sign(cap,f.private['tim_brydges'],f.temp.name),prerequisites=prerequisite,
            key_loader=lambda _:f.keys,clock=lambda:f.now)
        self.payload=review

    def test_actual_consumed_qa_authenticates_before_scope_signature(self):
        signer=SecurityScopeSigner(policy=self.policy,kms=self,sts=self,enabled=True)
        self.assertEqual(len(signer.sign(self.payload,now=self.f.now)),64)
        self.assertEqual(self.calls,1)

    def test_tampered_qa_receipt_blocks_scope_signature(self):
        self.row['result_signature']={'S':base64.b64encode(b'x'*64).decode()}
        signer=SecurityScopeSigner(policy=self.policy,kms=self,sts=self,enabled=True)
        with self.assertRaises(StateError):signer.sign(self.payload,now=self.f.now)
        self.assertEqual(self.calls,0)

    def test_qa_consumption_removed_during_custody_read_blocks_signature(self):
        def revoke():
            self.f.states.load_state.return_value=replace(self.f.states.load_state.return_value,
                consumed_evidence_ids=frozenset())
        self.on_key=revoke
        signer=SecurityScopeSigner(policy=self.policy,kms=self,sts=self,enabled=True)
        with self.assertRaises(StateError):signer.sign(self.payload,now=self.f.now)
        self.assertEqual(self.calls,0)


if __name__ == '__main__':unittest.main()
