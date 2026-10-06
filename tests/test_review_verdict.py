import base64
from dataclasses import replace
from datetime import timedelta
import json
from types import SimpleNamespace
import unittest
from unittest.mock import Mock
from factory_runtime.review_verdict import ReviewBinding,BoundReviewValidator,PinnedPythonTestEvidence
from factory_state.model import StateError,TaskState,Lease,CONTROLLER_IDENTITY
from factory_state.scope import SignedScopeStore,canonical
from factory_runtime.worker import digest
import test_progression as fixtures
NOW=fixtures.NOW
from scripts.scope_dispatch_canary import sign


class VerdictTests(unittest.TestCase):
    def setUp(self):
        self.binding=ReviewBinding('factory','task-1','independent_inspector','a'*40,
            'sha256:'+'b'*64,'sha256:'+'c'*64,'d'*40,'sha256:'+'e'*64,
            'sha256:'+'f'*64,('fingerprint.py',))
        self.check=Mock(return_value=True)
        self.validator=BoundReviewValidator(self.binding,self.check)
        self.state=SimpleNamespace(factory_id='factory',task_id='task-1',state='INSPECTION',
            leases=[SimpleNamespace(lease_id='lease',role_id='independent_inspector')])
        self.request=SimpleNamespace(source_commit='a'*40,contract_digest=self.binding.contract_digest,
            input_digest=self.binding.input_digest,lease_id='lease')
        self.value={k:getattr(self.binding,k) for k in self.binding.__dataclass_fields__ if k!='allowed_paths'}
        self.value.update(kind='factory_review_v1',verdict='ACCEPTED',rationale='Reviewed exact candidate.',findings=[])
    def run_review(self):return self.validator(self.state,self.request,canonical(self.value))
    def test_exact_acceptance_requires_independent_boolean_test_success(self):
        self.assertTrue(self.run_review())
        self.check.assert_called_once_with('d'*40,'sha256:'+'e'*64,'sha256:'+'f'*64)
        for answer in (False,None,1,'passed'):
            self.check.return_value=answer;self.assertFalse(self.run_review())
    def test_rejection_blockers_wrong_bindings_and_extra_claims_never_check_tests(self):
        original=dict(self.value)
        for changes in ({'verdict':'REJECTED'},{'candidate_commit':'0'*40},{'task_id':'other'},
                {'tests_passed':True},{'rationale':' '},{'findings':[{'severity':'high','path':'fingerprint.py','detail':'Broken'}]},
                {'findings':[{'severity':'low','path':'../secret','detail':'Broken'}]}):
            self.value={**original,**changes};self.assertFalse(self.run_review())
        self.check.assert_not_called()
    def test_duplicate_invalid_encoding_and_nonfinite_json_fail_closed(self):
        raw=canonical(self.value)
        for malformed in (raw[:-1]+b',"verdict":"ACCEPTED"}',raw.decode().encode('utf-16'),
                b'{"verdict":NaN}',b'[]',b'x'*32769):
            self.assertFalse(self.validator(self.state,self.request,malformed))
        self.check.assert_not_called()
    def test_stale_state_or_request_cannot_use_a_valid_verdict(self):
        self.request.source_commit='1'*40;self.assertFalse(self.run_review())
        self.request.source_commit='a'*40;self.state.state='PAUSED';self.assertFalse(self.run_review())
        self.state.state='INSPECTION';self.state.leases=[];self.assertFalse(self.run_review())
        self.check.assert_not_called()
    def test_no_default_validator_or_unrelated_gate(self):
        with self.assertRaises(StateError):BoundReviewValidator(self.binding,None)
        with self.assertRaises(StateError):BoundReviewValidator(replace(self.binding,role_id='deep_security_reviewer'),self.check)
        with self.assertRaises(StateError):BoundReviewValidator(replace(self.binding,allowed_paths=('../secret',)),self.check)
    def test_qa_uses_same_independent_test_requirement(self):
        self.binding=replace(self.binding,role_id='qa_engineer')
        self.validator=BoundReviewValidator(self.binding,self.check)
        self.state.state='QA';self.state.leases[0].role_id='qa_engineer';self.value['role_id']='qa_engineer'
        self.check.return_value=False;self.assertFalse(self.run_review())
        self.check.return_value=True;self.assertTrue(self.run_review())


class TestEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.files={'fingerprint.py':'print("fixture")\n'}
        import hashlib
        self.proof={'source_commit':'a'*40,'candidate_commit':'d'*40,
            'observed_at':NOW.isoformat(),'runtime':'python3.12-linux','python_version':'3.12.15',
            'files':{p:hashlib.sha256(v.encode()).hexdigest() for p,v in self.files.items()},
            'exit_code':0,'credentials_in_environment':False,'stdout':'',
            'stderr':'test_fixture ... ok\n\nRan 1 tests in 0.001s\n\nOK\n'}
    def verifier(self,**changes):
        raw=canonical({**self.proof,**changes})
        binding=ReviewBinding('factory','task-1','qa_engineer','a'*40,
            'sha256:'+'b'*64,'sha256:'+'c'*64,'d'*40,digest(canonical(self.files)),
            digest(raw),tuple(self.files))
        return PinnedPythonTestEvidence(binding,raw,self.files,test_count=1,clock=lambda:NOW)
    def check(self,verifier):
        b=verifier.binding
        return verifier(b.candidate_commit,b.candidate_digest,b.test_evidence_digest)
    def test_exact_independent_artifact_and_freshness(self):
        self.assertTrue(self.check(self.verifier()))
        for offset in (-3601,1):
            self.assertFalse(self.check(self.verifier(observed_at=(NOW+timedelta(seconds=offset)).isoformat())))
        self.assertFalse(self.check(self.verifier(observed_at=NOW.replace(tzinfo=None).isoformat())))
    def test_failures_skips_wrong_runtime_and_candidate_are_rejected(self):
        for change in ({'exit_code':False},{'exit_code':1},{'credentials_in_environment':True},
                {'stderr':'Ran 1 tests in 0.01s\n\nOK (skipped=1)\n'},
                {'stderr':'Ran 2 tests in 0.01s\n\nOK\n'}, {'stdout':'unexpected'},
                {'runtime':'python3.12-windows'},{'python_version':'3.13.1'},
                {'candidate_commit':'e'*40},{'source_commit':'e'*40},{'files':{}}):
            with self.subTest(change=change):self.assertFalse(self.check(self.verifier(**change)))
    def test_tampered_bytes_and_wrong_call_binding_fail(self):
        verifier=self.verifier();b=verifier.binding
        self.assertFalse(verifier('e'*40,b.candidate_digest,b.test_evidence_digest))
        with self.assertRaises(StateError):
            PinnedPythonTestEvidence(b,b'{}',self.files,test_count=1)
        with self.assertRaises(StateError):
            PinnedPythonTestEvidence(b,verifier.raw,{'fingerprint.py':'tampered'},test_count=1)


class SignedProgressionVerdictTests(unittest.TestCase):
    def test_real_signed_inspector_result_advances_only_after_bound_tests(self):
        f=fixtures.SignedResultProgressionTests();f.setUp();self.addCleanup(f.doCleanups)
        lease=Lease('lease-1','independent_inspector','independent_inspector_service',NOW+timedelta(minutes=10))
        f.states.state=TaskState('factory','task-1','INSPECTION',3,NOW,CONTROLLER_IDENTITY,(lease,))
        scope=SignedScopeStore('state',f.client,f.keys)
        review={'kind':'scope_review','factory_id':'factory','task_id':'task-1',
            'binding':f.ledger._binding(f.request),'verdict':'ACCEPTED',
            'reviewer_identity':'product_spec_reviewer_service','rationale':'Independent scope review',
            'issued_at':int(NOW.timestamp()),'expires_at':int(NOW.timestamp())+300}
        scope.approve_task(f.states.state,f.request,review,sign(review,f.private['product_spec_reviewer_service'],f.directory.name),now=NOW)
        binding=ReviewBinding('factory','task-1','independent_inspector',f.request.source_commit,
            f.request.contract_digest,f.request.input_digest,'d'*40,'sha256:'+'e'*64,'sha256:'+'f'*64,('fingerprint.py',))
        value={k:getattr(binding,k) for k in binding.__dataclass_fields__ if k!='allowed_paths'}
        value.update(kind='factory_review_v1',verdict='ACCEPTED',rationale='Bound review',findings=[])
        output=canonical(value)
        row=f.client.items[f.client.key(f.ledger._key(f.state,f.request))]
        payload=json.loads(row['result_payload']['S']);payload.update(producer_identity=lease.authoritative_identity,output_digest=digest(output))
        row.update(result_payload={'S':canonical(payload).decode()},receipt_digest={'S':digest(canonical(payload))},
            result_signature={'S':base64.b64encode(sign(payload,f.private[lease.authoritative_identity],f.directory.name)).decode()},
            result_output={'S':base64.b64encode(output).decode()})
        check=Mock(return_value=False);f.progressor.review_validator=BoundReviewValidator(binding,check)
        with self.assertRaises(StateError):f.progressor.advance('factory','task-1',f.request)
        self.assertEqual(f.states.writes,[])
        check.return_value=True
        self.assertEqual(f.progressor.advance('factory','task-1',f.request)['state'],'QA')
        self.assertEqual(len(f.states.writes),1)
        self.assertEqual(f.progressor.advance('factory','task-1',f.request)['status'],'ALREADY_ADVANCED')
        self.assertEqual(check.call_count,2)
