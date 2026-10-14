from dataclasses import replace
from datetime import timedelta
import json
import unittest

from factory_runtime.security_capability_signing import check_plan, SecurityCapabilitySigner
from factory_runtime.review_signing import KEYS, ROLES
from factory_state.model import StateError
from factory_state.signers import public_key_der
from factory_state.kms_signer import ALGORITHM
from scripts.scope_dispatch_canary import sign
import test_security_scope_policy as fixtures


class CapabilityTests(unittest.TestCase):
    def setUp(self):
        self.f=fixtures.SecurityScopeTests();self.f.setUp();self.addCleanup(self.f.doCleanups)
        self.material=self.f.args['material'];self.plan=self.f.args['plan'];self.calls=0

    def get_caller_identity(self):
        return {'Account':'666730517561','Arn':f"arn:aws:sts::666730517561:assumed-role/{ROLES['owner']}/test"}

    def get_public_key(self, **kwargs):
        return {'KeyId':KEYS['owner'],'KeySpec':'ECC_NIST_EDWARDS25519','KeyUsage':'SIGN_VERIFY',
            'SigningAlgorithms':[ALGORITHM],'PublicKey':public_key_der(self.f.keys['tim_brydges'])}

    def sign(self, **kwargs):
        self.calls+=1
        return {'KeyId':KEYS['owner'],'SigningAlgorithm':ALGORITHM,
            'Signature':sign(json.loads(kwargs['Message']),self.f.private['tim_brydges'],self.f.temp.name)}

    def signer(self, enabled=False):
        return SecurityCapabilitySigner(material=self.material,plan=self.plan,kms=self,sts=self,
            key_loader=lambda _:self.f.keys,clock=lambda:self.f.now,enabled=enabled)

    def test_exact_capability_signs_once_with_owner_custody(self):
        signer=self.signer(True)
        self.assertEqual(len(signer.sign(self.plan.capability_payload,now=self.f.now)),64)
        with self.assertRaises(StateError):signer.sign(self.plan.capability_payload,now=self.f.now)
        self.assertEqual(self.calls,1)

    def test_disabled_and_substituted_payload_cannot_sign(self):
        with self.assertRaises(StateError):self.signer().sign(self.plan.capability_payload,now=self.f.now)
        with self.assertRaises(StateError):self.signer(True).sign({**self.plan.capability_payload,'stop_condition':'release'},now=self.f.now)
        self.assertEqual(self.calls,0)

    def test_wrong_stage_lease_role_version_and_receipt_rejected(self):
        for plan in (replace(self.plan,state='QA'),replace(self.plan,state_version=True),
                replace(self.plan,lease=replace(self.plan.lease,role_id='qa_engineer',authoritative_identity='qa_engineer_service')),
                replace(self.plan,lease=replace(self.plan.lease,expires_at=self.f.now+timedelta(hours=1))),
                replace(self.plan,review_payload={**self.plan.review_payload,'reviewer_identity':'tim_brydges'}),
                replace(self.plan,capability_payload={**self.plan.capability_payload,'capability_id':'bounded-review-qa'})):
            with self.subTest(plan=plan),self.assertRaises(StateError):check_plan(self.material,plan,self.f.now)

    def test_stale_proof_rejected(self):
        with self.assertRaises(StateError):check_plan(self.material,self.plan,self.f.now+timedelta(hours=2))
