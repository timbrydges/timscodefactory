import copy
import base64
import hashlib
import sys
import unittest
from datetime import timedelta
from pathlib import Path
from unittest.mock import Mock,patch
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding,PublicFormat

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'scripts'))
import sign_qa_recovery003_allowance as p
import test_qa_recovery003_authorization as previous


class RecoverySigningTests(unittest.TestCase):
    def setUp(self):
        fixture=previous.RecoveryAuthorizationTests();fixture.setUp();self.now=fixture.args['now']
        self.plan=fixture.plan;self.plan['kind']='qa_recovery003_signing_plan'
        doc=self.plan['activation'];del doc['role']
        doc.update(kind='qa_recovery003_activation',capture_failed_review_response=True)
        self.plan['activation_sha256']=hashlib.sha256(p.canonical(doc)).hexdigest()
        payload=self.plan['allowance_payload']
        payload.update(kind=p.KIND,candidate_commit=p.CANDIDATE,recovery_scope_digest='sha256:'+p.SCOPE_SHA256,
            attempt_table=p.TABLE,attempt_key=p.PK,capture_failed_review_response=True,maximum_captured_response_bytes=262144)
        self.plan['allowance_payload_digest']=p.digest(payload)

    def validate(self,plan=None,**kw):
        plan=self.plan if plan is None else plan
        return p.validate_plan(plan,root=ROOT,approved_digest=kw.get('digest',p.digest(plan)),now=kw.get('now',self.now))

    def test_recovery_plan_validates_without_aws(self):
        self.assertEqual(self.validate(),self.plan['allowance_payload'])
        self.assertEqual(self.validate()['attempt_table'],p.TABLE)

    def test_consumed_recovery002_plan_cannot_authorize_recovery003(self):
        import test_qa_recovery002_signing as consumed
        fixture=consumed.RecoverySigningTests();fixture.setUp()
        kms=Mock();sts=Mock()
        with self.assertRaises(p.StateError):
            p.sign(fixture.plan,root=ROOT,approved_digest=p.digest(fixture.plan),kms=kms,sts=sts,now=self.now)
        self.assertEqual(kms.mock_calls,[]);self.assertEqual(sts.mock_calls,[])

    def test_old_model_cannot_be_relabelled_as_recovery003(self):
        plan=copy.deepcopy(self.plan)
        plan['activation']['qualification']['model_id']='gemini-3.8-flash'
        plan['activation_sha256']=hashlib.sha256(p.canonical(plan['activation'])).hexdigest()
        kms=Mock();sts=Mock()
        with self.assertRaises(p.StateError):
            p.sign(plan,root=ROOT,approved_digest=p.digest(plan),kms=kms,sts=sts,now=self.now)
        self.assertEqual(kms.mock_calls,[]);self.assertEqual(sts.mock_calls,[])

    def test_old_or_expanded_authority_rejected_before_aws(self):
        for field,value in (('kind','pilot002_exact_request_allowance'),('attempt_table','tims-factory-pilot-002-attempts'),
                           ('maximum_provider_calls',2),('retries',1),('approved_cap_micro_usd',250001),
                           ('capture_failed_review_response',False),('gate_authority',True)):
            plan=copy.deepcopy(self.plan);plan['allowance_payload'][field]=value
            plan['allowance_payload_digest']=p.digest(plan['allowance_payload']);kms=Mock();sts=Mock()
            with self.assertRaises(Exception):p.sign(plan,root=ROOT,approved_digest=p.digest(plan),kms=kms,sts=sts,now=self.now)
            self.assertEqual(kms.mock_calls,[]);self.assertEqual(sts.mock_calls,[])
        for change in ({'kind':'pilot002_signing_plan'},{'extra':'override'}):
            with self.assertRaises(Exception):self.validate({**self.plan,**change})
        with self.assertRaises(Exception):self.validate(digest='sha256:'+'0'*64)
        with self.assertRaises(Exception):self.validate(now=self.now+timedelta(minutes=21))
        plan=copy.deepcopy(self.plan);plan['evidence']['substitution']=True
        with self.assertRaises(Exception):self.validate(plan)

    def test_exact_signature_checked_and_uncertain_signing_never_retried(self):
        key=Ed25519PrivateKey.generate();pem=key.public_key().public_bytes(Encoding.PEM,PublicFormat.SubjectPublicKeyInfo)
        binding={'key_arn':self.plan['kms_key_arn'],'fingerprint':'synthetic'}
        sts=Mock();sts.get_caller_identity.return_value={'Account':'666730517561',
            'Arn':'arn:aws:sts::666730517561:assumed-role/tims-factory-signing-owner/test'}
        for fail in (False,True):
            kms=Mock()
            if fail:kms.sign.side_effect=RuntimeError('private provider detail')
            else:kms.sign.side_effect=lambda **kw:{'KeyId':binding['key_arn'],'SigningAlgorithm':p.ALGORITHM,'Signature':key.sign(kw['Message'])}
            with patch.object(p.EnrolledKmsReceiptSigner,'_enrollment',return_value=(binding,pem)),patch.object(p,'KmsReceiptSigner',return_value=Mock(pem=pem)):
                if fail:
                    with self.assertRaisesRegex(p.StateError,'^Recovery signing stopped; reconcile without retry$'):
                        p.sign(self.plan,root=ROOT,approved_digest=p.digest(self.plan),kms=kms,sts=sts,now=self.now)
                else:
                    result=p.sign(self.plan,root=ROOT,approved_digest=p.digest(self.plan),kms=kms,sts=sts,now=self.now)
                    self.assertEqual(result['payload'],self.plan['allowance_payload'])
            self.assertEqual(kms.sign.call_count,1)

    def test_root_cannot_sign_and_bounded_json_is_required(self):
        kms=Mock();sts=Mock();sts.get_caller_identity.return_value={'Account':'666730517561','Arn':'arn:aws:iam::666730517561:root'}
        with self.assertRaises(Exception):p.sign(self.plan,root=ROOT,approved_digest=p.digest(self.plan),kms=kms,sts=sts,now=self.now)
        kms.sign.assert_not_called()
        for raw in (b'x'*49153,b'{"kind":1,"kind":2}',b'[]'):
            with self.assertRaises(Exception):p.input_plan(base64.b64encode(raw).decode())
        for encoded in ('','not-base64',None):
            with self.assertRaises(Exception):p.input_plan(encoded)
        self.assertEqual(p.input_plan(base64.b64encode(p.canonical(self.plan)).decode()),self.plan)

    def test_short_window_and_paid_qa_rejected_before_kms(self):
        expiry=self.plan['allowance_payload']['expires_at']
        from datetime import datetime,timezone
        for when in (expiry-60,expiry,expiry+1):
            kms=Mock();sts=Mock()
            with self.assertRaises(Exception):
                p.sign(self.plan,root=ROOT,approved_digest=p.digest(self.plan),kms=kms,sts=sts,
                    now=datetime.fromtimestamp(when,timezone.utc))
            self.assertEqual(kms.mock_calls,[]);self.assertEqual(sts.mock_calls,[])
        bad=copy.deepcopy(self.plan)
        bad['activation']['qualification']['billing_observation']['billing_account_linked']=True
        bad['activation_sha256']=hashlib.sha256(p.canonical(bad['activation'])).hexdigest()
        with self.assertRaises(Exception):self.validate(bad)
        bad=copy.deepcopy(self.plan);bad['pricing']['maximum_cost_micro_usd']=1
        with self.assertRaises(Exception):self.validate(bad)

    def test_workflow_only_owner_main_first_attempt_and_exclusive(self):
        import yaml
        jobs=yaml.safe_load((ROOT/'.github/workflows/factory-owner-signing.yml').read_text())['jobs']
        job=jobs['sign_qa_recovery003_allowance']
        for guard in ("github.ref == 'refs/heads/main'","github.actor_id == '214414801'",'github.run_attempt == 1',
                      "inputs.pilot002_reviewer_plan_digest == ''","inputs.pilot002_builder_plan_digest == ''",
                      "inputs.google_proposal_base64 == ''","inputs.owner_plan_base64 == ''",'inputs.receipt_iam_canary == false'):
            self.assertIn(guard,job['if'])
        self.assertEqual(job['environment'],'production');self.assertEqual(job['env']['AWS_MAX_ATTEMPTS'],'1')
        self.assertIn("inputs.qa_recovery003_plan_base64 != ''",job['if'])
        self.assertIn("inputs.inspector_recovery001_plan_digest == ''",job['if'])
        for name,value in jobs.items():
            if name!='sign_qa_recovery003_allowance':
                self.assertIn("inputs.qa_recovery003_plan_digest == ''",value['if'])
                self.assertIn("inputs.qa_recovery003_plan_base64 == ''",value['if'])
        commands='\n'.join(step.get('run','') for step in job['steps'])
        self.assertNotIn('${{',commands);self.assertNotIn('invoke',commands)


if __name__=='__main__':unittest.main()
