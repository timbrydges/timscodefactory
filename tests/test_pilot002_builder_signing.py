import base64
import copy
import json
from datetime import datetime,timezone
from pathlib import Path
import sys
import unittest
from unittest.mock import Mock,patch
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding,PublicFormat
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
import sign_pilot002_builder_allowance as p


class BuilderSigningTests(unittest.TestCase):
    def setUp(self):
        self.root=Path(__file__).resolve().parents[1]
        self.plan=json.loads((self.root/'factory/evidence/pilot-002-builder-live-review-candidate.json').read_text())
        self.now=datetime.fromisoformat(self.plan['prepared_at'])

    def validate(self,plan=None,now=None,digest=None):
        plan=plan or self.plan
        return p.validate_plan(plan,root=self.root,approved_digest=digest or p.digest(plan),now=now or self.now)

    def test_reviewed_plan_passes_offline(self):
        self.assertEqual(self.validate(),self.plan['allowance_payload'])

    def test_wrong_digest_and_expiry_rejected_before_kms(self):
        for digest,now in [('sha256:'+'0'*64,self.now),(p.digest(self.plan),datetime.fromtimestamp(self.plan['allowance_payload']['expires_at'],timezone.utc))]:
            kms=Mock()
            with self.assertRaises(Exception):p.sign(self.plan,root=self.root,approved_digest=digest,kms=kms,sts=Mock(),now=now)
            kms.sign.assert_not_called()

    def test_cap_retry_role_source_and_evidence_mutations_rejected(self):
        for field,value in [('approved_cap_micro_usd',250001),('retries',1),('maximum_provider_calls',2),('production_release_authorized',True)]:
            plan=copy.deepcopy(self.plan);plan['allowance_payload'][field]=value
            with self.assertRaises(Exception):self.validate(plan)
        for patcher in (lambda x:x['activation'].update(role='qa'),lambda x:x['activation'].update(source_commit='0'*40),
                        lambda x:x['evidence'].update(unreviewed=True)):
            plan=copy.deepcopy(self.plan);patcher(plan)
            with self.assertRaises(Exception):self.validate(plan)

    def test_isolated_signing_returns_locally_verified_signature_once(self):
        key=Ed25519PrivateKey.generate();pem=key.public_key().public_bytes(Encoding.PEM,PublicFormat.SubjectPublicKeyInfo)
        binding={'key_arn':self.plan['kms_key_arn'],'fingerprint':'test-fingerprint'}
        enrollment=Mock();enrollment._enrollment.return_value=(binding,pem)
        kms=Mock();kms.sign.side_effect=lambda **kw:{'KeyId':binding['key_arn'],'SigningAlgorithm':p.ALGORITHM,'Signature':key.sign(kw['Message'])}
        sts=Mock();sts.get_caller_identity.return_value={'Account':'666730517561','Arn':'arn:aws:sts::666730517561:assumed-role/tims-factory-signing-owner/test'}
        with patch.object(p,'EnrolledKmsReceiptSigner',return_value=enrollment),patch.object(p,'KmsReceiptSigner',return_value=Mock(pem=pem)):
            result=p.sign(self.plan,root=self.root,approved_digest=p.digest(self.plan),kms=kms,sts=sts,now=self.now)
        key.public_key().verify(base64.b64decode(result['signature']),p.canonical(result['payload']))
        self.assertEqual(kms.sign.call_count,1)

    def test_root_session_cannot_sign(self):
        kms=Mock();sts=Mock();sts.get_caller_identity.return_value={'Account':'666730517561','Arn':'arn:aws:iam::666730517561:root'}
        with self.assertRaises(Exception):p.sign(self.plan,root=self.root,approved_digest=p.digest(self.plan),kms=kms,sts=sts,now=self.now)
        kms.sign.assert_not_called()

    def test_uncertain_signing_is_never_retried(self):
        pem=self.plan['activation']['signer_registry']['signers'][0]['public_key_pem'].encode()
        binding={'key_arn':self.plan['kms_key_arn'],'fingerprint':'test-fingerprint'}
        enrollment=Mock();enrollment._enrollment.return_value=(binding,pem)
        kms=Mock();kms.sign.side_effect=TimeoutError('uncertain')
        sts=Mock();sts.get_caller_identity.return_value={'Account':'666730517561','Arn':'arn:aws:sts::666730517561:assumed-role/tims-factory-signing-owner/test'}
        with patch.object(p,'EnrolledKmsReceiptSigner',return_value=enrollment),patch.object(p,'KmsReceiptSigner',return_value=Mock(pem=pem)):
            with self.assertRaises(TimeoutError):p.sign(self.plan,root=self.root,approved_digest=p.digest(self.plan),kms=kms,sts=sts,now=self.now)
        self.assertEqual(kms.sign.call_count,1)


if __name__=='__main__':unittest.main()
