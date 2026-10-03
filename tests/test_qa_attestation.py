import base64
import hashlib
import json
import os
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT/'src'), str(ROOT/'scripts')]
from factory_runtime import qa_attestation as qa
from factory_runtime.review_preparation import PACKET, REVIEW, BOOTSTRAP
from factory_state.model import StateError
from factory_state.scope import SignedScopeStore, canonical
from factory_state.signers import public_key_der
from scope_dispatch_canary import fixture_keys, sign


class QaAttestationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.report = qa.execute(ROOT)

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        for name in (PACKET, REVIEW, BOOTSTRAP):
            path = self.root/name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes((ROOT/name).read_bytes())
        self.keys, self.private = fixture_keys(self.root, (qa.IDENTITY,))
        self.now = datetime(2026,10,3,4,tzinfo=timezone.utc)
        self.commit = 'a'*40
        self.env = {qa.FLAG:'true', 'FACTORY_REVIEW_ROLE':'qa',
            'FACTORY_OPERATIONAL_EXECUTION_ENABLED':'false', 'FACTORY_REVIEW_KEY_ARN':qa.KEY,
            'FACTORY_QA_ATTESTATION_NONCE':'b'*32,
            'FACTORY_QA_ATTESTATION_EXPIRES_AT':str(int(self.now.timestamp())+300)}
        self.event = {'kind':'qa_execution_attestation', 'source_commit':self.commit,
            'candidate_commit':qa.CANDIDATE, 'nonce':'b'*32}
        self.registry = {'schema_version':'1.0', 'enabled':True, 'signers':[{
            'identity':qa.IDENTITY, 'public_key_pem':self.keys[qa.IDENTITY].decode(),
            'fingerprint':'sha256:'+hashlib.sha256(public_key_der(self.keys[qa.IDENTITY])).hexdigest(),
            'enrollment_commit':'c'*40, 'not_before':int(self.now.timestamp())-60,
            'expires_at':int(self.now.timestamp())+600, 'revoked':False}]}
        self.save_registry()
        self.kms = Mock()
        self.kms.get_public_key.return_value = {'KeyId':qa.KEY, 'KeyUsage':'SIGN_VERIFY',
            'KeySpec':'ECC_NIST_EDWARDS25519', 'SigningAlgorithms':[qa.ALGORITHM],
            'PublicKey':public_key_der(self.keys[qa.IDENTITY])}
        self.kms.sign.side_effect = lambda **kw: {'KeyId':qa.KEY, 'SigningAlgorithm':qa.ALGORITHM,
            'Signature':sign(json.loads(kw['Message']),self.private[qa.IDENTITY],self.root)}
        self.sts = Mock()
        self.sts.get_caller_identity.return_value = {'Account':'666730517561',
            'Arn':'arn:aws:sts::666730517561:assumed-role/tims-factory-review-qa/test'}
        self.clock = Mock(return_value=self.now)

    def save_registry(self):
        path = self.root/qa.REGISTRY
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(self.registry))

    def attest(self):
        with patch.object(qa, 'execute', return_value=self.report):
            return qa.attest(self.event, root=self.root, commit=self.commit, env=self.env,
                             kms=self.kms, sts=self.sts, clock=self.clock)

    def test_real_signature_binds_report_and_never_grants_gate(self):
        result = self.attest()
        self.kms.sign.assert_called_once()
        self.assertLessEqual(len(self.kms.sign.call_args.kwargs['Message']),4096)
        self.assertEqual(result['payload']['report_digest'],self.report['report_digest'])
        self.assertFalse(result['payload']['gate_authority'])
        self.assertFalse(result['payload']['production_release_authorized'])
        signature = base64.b64decode(result['signature_base64'])
        verifier = SignedScopeStore('unused',None,self.keys)
        verifier._verify(result['payload'],signature,qa.IDENTITY,self.now)
        with self.assertRaises(StateError):
            verifier._verify({**result['payload'],'gate_authority':True},signature,qa.IDENTITY,self.now)

    def test_disabled_handler_rejects_before_files_or_clients(self):
        with patch.dict(os.environ,{},clear=True), patch.object(Path,'read_bytes') as read:
            with self.assertRaisesRegex(StateError,'disabled'): qa.handler({},None)
            read.assert_not_called()

    def test_wrong_event_or_controls_never_sign(self):
        for field,value in [('nonce','d'*32),('candidate_commit','d'*40),('extra',True),('kind','qa_gate')]:
            with self.subTest(field=field):
                with patch.dict(self.event,{field:value}):
                    with self.assertRaises(StateError): self.attest()
        for field,value in [(qa.FLAG,'false'),('FACTORY_OPERATIONAL_EXECUTION_ENABLED','true'),
            ('FACTORY_REVIEW_ROLE','security'),('FACTORY_REVIEW_KEY_ARN','other'),
            ('FACTORY_QA_ATTESTATION_EXPIRES_AT',str(int(self.now.timestamp())+301))]:
            with self.subTest(field=field), patch.dict(self.env,{field:value}):
                with self.assertRaises(StateError): self.attest()
        self.kms.sign.assert_not_called()
        self.sts.get_caller_identity.assert_not_called()

    def test_expired_revoked_or_short_enrollment_never_signs(self):
        for changes in ({'expires_at':int(self.now.timestamp())}, {'revoked':True},
                        {'expires_at':int(self.now.timestamp())+299}):
            with patch.dict(self.registry['signers'][0],changes):
                self.save_registry()
                with self.assertRaises(StateError): self.attest()
        self.kms.sign.assert_not_called()

    def test_wrong_cloud_role_or_key_never_signs(self):
        original = self.sts.get_caller_identity.return_value.copy()
        for value in ('arn:aws:sts::666730517561:assumed-role/tims-factory-review-security/test',
                      'arn:aws:sts::666730517561:assumed-role/tims-factory-review-qa/'):
            self.sts.get_caller_identity.return_value['Arn'] = value
            with self.assertRaises(StateError): self.attest()
        self.sts.get_caller_identity.return_value = original
        self.kms.get_public_key.return_value['KeyId'] = 'wrong'
        with self.assertRaises(StateError): self.attest()
        self.kms.sign.assert_not_called()

    def test_tests_outliving_approval_never_sign(self):
        self.clock.side_effect = [self.now,self.now+timedelta(seconds=300)]
        with self.assertRaises(StateError): self.attest()
        self.kms.sign.assert_not_called()

    def test_tampered_report_rejected_and_failed_tests_not_relabelled(self):
        original = self.report
        self.report = {**original,'case_count':17}
        with self.assertRaises(StateError): self.attest()
        self.kms.sign.assert_not_called()
        self.report = json.loads(json.dumps(original))
        self.report['cases'][0]['passed'] = False
        self.report['status'] = 'LOCAL_QA_FAILED_UNSIGNED'
        del self.report['report_digest']
        self.report['report_digest'] = 'sha256:'+hashlib.sha256(canonical(self.report)).hexdigest()
        self.assertFalse(self.attest()['payload']['cases_passed'])

    def test_uncertain_or_invalid_signatures_never_retry(self):
        for outcome in (RuntimeError('sensitive provider detail'),
                        {'KeyId':qa.KEY,'SigningAlgorithm':qa.ALGORITHM,'Signature':b'x'*64}):
            self.kms.sign.reset_mock()
            self.kms.sign.side_effect = outcome if isinstance(outcome,Exception) else None
            self.kms.sign.return_value = outcome
            with self.assertRaisesRegex(StateError,'uncertain.*never retry'): self.attest()
            self.kms.sign.assert_called_once()


if __name__ == '__main__': unittest.main()
