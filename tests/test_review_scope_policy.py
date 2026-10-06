"""Synthetic task/test fixtures only; real signatures exercise scope authority."""
import hashlib
import json
import tempfile
import unittest
from dataclasses import replace
from datetime import timedelta

from factory_state.dispatch import DynamoDBDispatchStore
from factory_state.model import CONTROLLER_IDENTITY, TaskState, StateError
from factory_state.scope import canonical
from factory_state.signers import public_key_der
from factory_state.kms_signer import ALGORITHM
from factory_runtime.intake import AuthenticatedIntakeService
from factory_runtime.review_provider_protocol import job_input, prepare
from factory_runtime.review_verdict import ReviewBinding, PinnedPythonTestEvidence
from factory_runtime.review_scope_policy import (contract, FixedScopeReview, ReviewScopeSigner,
    IDENTITY, EVIDENCE, STOP, RATIONALE, FACTORY, TASK, STAGES, ROLE_IDS)
from factory_runtime.worker import digest
from scripts.scope_dispatch_canary import fixture_keys, sign
from test_autonomous_scheduler import NOW, States


class ScopePolicyTests(unittest.TestCase):
    def setUp(self):
        self.directory=tempfile.TemporaryDirectory();self.addCleanup(self.directory.cleanup)
        self.keys,self.private=fixture_keys(self.directory.name,('tim_brydges',IDENTITY))
        self.now=NOW;self.sign_calls=[];self.on_key=lambda:None

    def material(self,role='inspector'):
        files={'fingerprint.py':'def fingerprint(x): return x\n','tests/test_fingerprint.py':'# fixture\n'}
        proof=canonical({'source_commit':'a'*40,'candidate_commit':'b'*40,'observed_at':NOW.isoformat(),
            'runtime':'python3.12-linux','python_version':'3.12.15',
            'files':{p:hashlib.sha256(v.encode()).hexdigest() for p,v in files.items()},
            'exit_code':0,'credentials_in_environment':False,'stdout':'',
            'stderr':'Ran 17 tests in 0.001s\n\nOK\n'})
        raw=contract(source_commit='a'*40,candidate_commit='b'*40,
                     candidate_digest=digest(canonical(files)),test_evidence_digest=digest(proof))
        inp=job_input(role=role,source_commit='a'*40,contract_digest=digest(raw),
                      candidate_commit='b'*40,files=files,test_evidence_digest=digest(proof))
        self.states=States(TaskState(FACTORY,TASK,STAGES[role],0,NOW,CONTROLLER_IDENTITY))
        intake=AuthenticatedIntakeService(self.states,DynamoDBDispatchStore('unused',None),
                                          key_loader=lambda _:self.keys,clock=lambda:NOW)
        plan=intake.prepare(FACTORY,TASK,role_id=ROLE_IDS[role],source_commit='a'*40,
            objective_id=TASK,capability_id='bounded-review',contract_bytes=raw,input_bytes=inp,
            reviewer_identity=IDENTITY,required_evidence=EVIDENCE,stop_condition=STOP,rationale=RATIONALE)
        prepared=prepare(role=role,request=plan.request,candidate_commit='b'*40,files=files,
                         test_evidence_digest=digest(proof),input_bytes=inp)
        binding=ReviewBinding(FACTORY,TASK,'independent_inspector','a'*40,digest(raw),digest(inp),'b'*40,
                             digest(canonical(files)),digest(proof),tuple(files))
        evidence=PinnedPythonTestEvidence(binding,proof,files,test_count=17,clock=lambda:self.now)
        return dict(plan=plan,prepared=prepared,contract_bytes=raw,
            owner_signature=sign(plan.capability_payload,self.private['tim_brydges'],self.directory.name),
            test_evidence=evidence,states=self.states,key_loader=lambda _:dict(self.keys),clock=lambda:self.now)

    def get_caller_identity(self):
        return {'Account':'666730517561','Arn':'arn:aws:sts::666730517561:assumed-role/tims-factory-signing-spec-reviewer/test'}

    def get_public_key(self,**kw):
        self.on_key()
        return {'KeyId':ReviewScopeSigner.key_bindings['spec'],'KeySpec':'ECC_NIST_EDWARDS25519',
            'KeyUsage':'SIGN_VERIFY','SigningAlgorithms':[ALGORITHM],'PublicKey':public_key_der(self.keys[IDENTITY])}

    def sign(self,**kw):
        self.sign_calls.append(kw)
        return {'KeyId':kw['KeyId'],'SigningAlgorithm':ALGORITHM,
            'Signature':sign(json.loads(kw['Message']),self.private[IDENTITY],self.directory.name)}

    def test_all_three_scopes_are_independently_checked_and_signed(self):
        for role in STAGES:
            args=self.material(role);policy=FixedScopeReview(**args)
            payload=policy.review(now=NOW)
            self.assertEqual(payload,args['plan'].review_payload)
            signer=ReviewScopeSigner(policy=policy,kms=self,sts=self,enabled=True)
            self.assertEqual(len(signer.sign(payload,now=NOW)),64)
            with self.assertRaises(StateError):signer.sign(payload,now=NOW)
        self.assertEqual(len(self.sign_calls),3)

    def test_owner_signature_cannot_be_replaced_by_custody_or_boolean(self):
        args=self.material();args['owner_signature']=b'0'*64
        with self.assertRaises(StateError):FixedScopeReview(**args).review(now=NOW)
        args['owner_signature']=True
        with self.assertRaises(StateError):FixedScopeReview(**args)

    def test_expanded_work_and_owner_signed_weakened_stop_rejected(self):
        args=self.material();args['contract_bytes']+=b' '
        with self.assertRaises(StateError):FixedScopeReview(**args).review(now=NOW)
        args=self.material();args['plan'].capability_payload['stop_condition']='continue to production'
        args['owner_signature']=sign(args['plan'].capability_payload,self.private['tim_brydges'],self.directory.name)
        with self.assertRaises(StateError):FixedScopeReview(**args).review(now=NOW)

    def test_self_review_changed_dispatch_and_unbounded_lease_rejected(self):
        for change in ('self','dispatch','lease','rationale'):
            args=self.material();p=args['plan']
            if change=='self':p.review_payload['reviewer_identity']='independent_inspector_service'
            if change=='dispatch':p=replace(p,request=replace(p.request,lease_id='another'))
            if change=='lease':p=replace(p,lease=replace(p.lease,expires_at=NOW+timedelta(hours=1)))
            if change=='rationale':p.review_payload['rationale']='identity canary passed'
            args['plan']=p
            with self.subTest(change=change),self.assertRaises(StateError):FixedScopeReview(**args).review(now=NOW)

    def test_paused_state_during_kms_key_read_stops_signing(self):
        args=self.material();policy=FixedScopeReview(**args)
        self.on_key=lambda:setattr(self.states,'state',replace(self.states.state,state='PAUSED'))
        signer=ReviewScopeSigner(policy=policy,kms=self,sts=self,enabled=True)
        with self.assertRaises(StateError):signer.sign(args['plan'].review_payload,now=NOW)
        self.assertEqual(self.sign_calls,[])

    def test_stale_proof_state_version_and_owner_revocation_rejected(self):
        for change in ('proof','version','owner'):
            args=self.material();policy=FixedScopeReview(**args)
            if change=='proof':self.now=NOW+timedelta(hours=2)
            if change=='version':self.states.state=replace(self.states.state,version=1)
            if change=='owner':self.keys.pop('tim_brydges')
            with self.subTest(change=change),self.assertRaises(StateError):policy.review(now=NOW)
            self.now=NOW

    def test_disabled_signer_and_substituted_receipt_cannot_sign(self):
        args=self.material();policy=FixedScopeReview(**args)
        with self.assertRaises(StateError):ReviewScopeSigner(policy=policy,kms=self,sts=self).sign(args['plan'].review_payload,now=NOW)
        signer=ReviewScopeSigner(policy=policy,kms=self,sts=self,enabled=True)
        with self.assertRaises(StateError):signer.sign({**args['plan'].review_payload,'verdict':'REJECTED'},now=NOW)
        self.assertEqual(self.sign_calls,[])
