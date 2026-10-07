"""Real fixture signatures and simulated AWS custody, no live signing."""
import json
from dataclasses import replace
import unittest
from unittest.mock import patch

import test_security_scope_policy as fixtures
from factory_runtime.security_scope_policy import SecurityScopeReview, SecurityScopeSigner, IDENTITY
from factory_runtime.security_qa_provenance import ConsumedQAProvenance
from factory_state.model import StateError
from factory_state.signers import public_key_der
from factory_state.kms_signer import ALGORITHM
from scripts.scope_dispatch_canary import sign


class SecuritySignerTests(unittest.TestCase):
    def setUp(self):
        self.f=fixtures.SecurityScopeTests();self.f.setUp();self.addCleanup(self.f.doCleanups)
        self.calls=0;self.on_key=lambda:None;self.fail=False
        self.policy=SecurityScopeReview(**self.f.args)
        self.payload=self.f.args['plan'].review_payload
        p=patch.object(ConsumedQAProvenance,'__call__',return_value=True)
        p.start();self.addCleanup(p.stop)

    def get_caller_identity(self):
        return {'Account':'666730517561',
            'Arn':'arn:aws:sts::666730517561:assumed-role/tims-factory-signing-spec-reviewer/test'}

    def get_public_key(self, **kwargs):
        self.on_key()
        return {'KeyId':SecurityScopeSigner.key_bindings['spec'],'KeySpec':'ECC_NIST_EDWARDS25519',
            'KeyUsage':'SIGN_VERIFY','SigningAlgorithms':[ALGORITHM],
            'PublicKey':public_key_der(self.f.keys[IDENTITY])}

    def sign(self, **kwargs):
        self.calls+=1
        if self.fail:raise TimeoutError('fixture uncertainty')
        return {'KeyId':kwargs['KeyId'],'SigningAlgorithm':ALGORITHM,
            'Signature':sign(json.loads(kwargs['Message']),self.f.private[IDENTITY],self.f.temp.name)}

    def signer(self, **kwargs):
        return SecurityScopeSigner(policy=self.policy,kms=self,sts=self,**kwargs)

    def test_signs_exact_policy_once(self):
        signer=self.signer(enabled=True)
        self.assertEqual(len(signer.sign(self.payload,now=self.f.now)),64)
        with self.assertRaises(StateError):signer.sign(self.payload,now=self.f.now)
        self.assertEqual(self.calls,1)

    def test_disabled_and_substituted_receipt_never_sign(self):
        with self.assertRaises(StateError):self.signer().sign(self.payload,now=self.f.now)
        with self.assertRaises(StateError):
            self.signer(enabled=True).sign({**self.payload,'rationale':'skip QA'},now=self.f.now)
        self.assertEqual(self.calls,0)

    def test_state_change_during_custody_read_stops_signature(self):
        def pause():
            self.f.states.load_state.return_value=replace(self.f.states.load_state.return_value,state='PAUSED')
        self.on_key=pause
        with self.assertRaises(StateError):self.signer(enabled=True).sign(self.payload,now=self.f.now)
        self.assertEqual(self.calls,0)

    def test_uncertain_signature_is_not_retried(self):
        self.fail=True;signer=self.signer(enabled=True)
        with self.assertRaises(TimeoutError):signer.sign(self.payload,now=self.f.now)
        with self.assertRaises(StateError):signer.sign(self.payload,now=self.f.now)
        self.assertEqual(self.calls,1)


if __name__ == '__main__':unittest.main()
