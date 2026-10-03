import base64
import copy
import json
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'src'))
from factory_runtime import qa_enrollment as enrollment
from factory_runtime.review_preparation import PACKET, REVIEW, BOOTSTRAP
from factory_state.model import StateError
from factory_state.signers import public_key_der


class QaEnrollmentTests(unittest.TestCase):
    def setUp(self):
        self.directory=tempfile.TemporaryDirectory(); self.addCleanup(self.directory.cleanup)
        self.root=Path(self.directory.name)
        for name in (PACKET,REVIEW,BOOTSTRAP,enrollment.BUNDLE,enrollment.PROOF,enrollment.REGISTRY):
            path=self.root/name; path.parent.mkdir(parents=True,exist_ok=True)
            path.write_bytes((ROOT/name).read_bytes())
        self.now=datetime(2026,10,3,3,10,tzinfo=timezone.utc)
        identity=json.loads((ROOT/BOOTSTRAP).read_bytes())['identities'][0]
        self.observation={'observed_at':self.now.isoformat(),'account':'666730517561',
            'key_arn':enrollment.KEY,'key_state':'Enabled','key_usage':'SIGN_VERIFY',
            'key_spec':'ECC_NIST_EDWARDS25519','algorithms':['ED25519_SHA_512'],
            'public_key_der_base64':base64.b64encode(public_key_der(identity['public_key_pem'].encode())).decode(),
            'fingerprint':identity['fingerprint'],'role_arn':enrollment.ROLE,
            'role_trust':{'Version':'2012-10-17','Statement':[{'Effect':'Allow',
                'Principal':{'Service':'lambda.amazonaws.com'},'Action':'sts:AssumeRole'}]}}

    def propose(self):
        return enrollment.propose(self.root,self.observation,now=self.now,enrollment_commit='a'*40)

    def test_one_qa_entry_preserves_existing_registry_and_never_applies_it(self):
        before=(self.root/enrollment.REGISTRY).read_bytes()
        result=self.propose(); old=json.loads(before)
        self.assertEqual(result['proposed_registry']['signers'][:-1],old['signers'])
        self.assertEqual(result['added_entry']['identity'],'qa_engineer_service')
        self.assertEqual(result['added_entry']['expires_at']-result['added_entry']['not_before'],86400)
        self.assertEqual((self.root/enrollment.REGISTRY).read_bytes(),before)
        self.assertFalse(result['gate_authority']); self.assertFalse(result['production_release_authorized'])

    def test_wrong_key_role_disabled_key_and_expanded_trust_rejected(self):
        original=copy.deepcopy(self.observation)
        for field,value in [('key_arn','other'),('public_key_der_base64','AAAA'),
            ('key_state','Disabled'),('role_arn',enrollment.ROLE.replace('-qa','-security')),
            ('role_trust',{'Version':'2012-10-17','Statement':[]})]:
            self.observation=copy.deepcopy(original); self.observation[field]=value
            with self.assertRaises(StateError): self.propose()

    def test_stale_future_and_naive_observation_rejected(self):
        for observed in (self.now-timedelta(seconds=3601),self.now+timedelta(seconds=1),self.now.replace(tzinfo=None)):
            self.observation['observed_at']=observed.isoformat()
            with self.assertRaises(StateError): self.propose()

    def test_changed_bundle_or_bootstrap_cannot_be_promoted(self):
        for name in (enrollment.BUNDLE,enrollment.PROOF,BOOTSTRAP):
            p=self.root/name; original=p.read_bytes(); p.write_bytes(original+b' ')
            with self.assertRaises(StateError): self.propose()
            p.write_bytes(original)

    def test_duplicate_qa_enrollment_and_disabled_registry_rejected(self):
        proposal=self.propose(); p=self.root/enrollment.REGISTRY; original=p.read_bytes()
        p.write_text(json.dumps(proposal['proposed_registry']))
        with self.assertRaises(StateError): self.propose()
        old=json.loads(original); old['enabled']=False; p.write_text(json.dumps(old))
        with self.assertRaises(StateError): self.propose()


if __name__=='__main__': unittest.main()
