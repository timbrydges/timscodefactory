import copy
import hashlib
import json
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

import test_google_qa_broker_runtime as fixtures
from factory_runtime import google_qa_broker_runtime as runtime
from factory_runtime.google_qa_authorization import digest
from factory_state.kms_signer import ALGORITHM
from factory_state.model import OWNER_IDENTITY, StateError
from factory_state.signers import public_key_der
from prepare_google_qa_free_allowance import proposal
from scope_dispatch_canary import sign
from sign_google_qa_free_allowance import sign_proposal


class OwnerSigningTests(unittest.TestCase):
    def setUp(self):
        self.fixture=fixtures.BrokerRuntimeTests(); self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.f=self.fixture.f; self.root=self.fixture.root
        self.f.free_tier(); self.fixture.manifest['pricing']=self.f.pricing
        raw=json.dumps(self.fixture.manifest).encode()
        (self.root/runtime.MANIFEST).write_bytes(raw)
        pin=patch.object(runtime,'ACTIVE_MANIFEST_SHA256',hashlib.sha256(raw).hexdigest())
        pin.start(); self.addCleanup(pin.stop)
        self.payload=proposal(self.root,source_commit=self.f.source,
            billing=self.f.payload['billing_evidence'],now=self.f.now)
        self.arn='arn:aws:kms:ca-central-1:666730517561:key/11111111-1111-1111-1111-111111111111'
        der=public_key_der(self.f.keys[OWNER_IDENTITY])
        (self.root/'factory/profiles/kms-signers.json').write_text(json.dumps({
            'schema_version':'1.0','signers':[{'signer':'owner','identity':OWNER_IDENTITY,
            'key_arn':self.arn,'fingerprint':'sha256:'+hashlib.sha256(der).hexdigest(),
            'enrollment_commit':'b'*40}]}))
        self.sts=Mock(); self.sts.get_caller_identity.return_value={
            'Account':'666730517561',
            'Arn':'arn:aws:sts::666730517561:assumed-role/tims-factory-signing-owner/fixture'}
        self.kms=Mock(); self.kms.get_public_key.return_value={'KeyId':self.arn,
            'KeyUsage':'SIGN_VERIFY','KeySpec':'ECC_NIST_EDWARDS25519',
            'SigningAlgorithms':[ALGORITHM],'PublicKey':der}
        def signing(**kwargs):
            self.assertEqual(kwargs['MessageType'],'RAW')
            self.assertEqual(kwargs['SigningAlgorithm'],ALGORITHM)
            self.assertEqual(kwargs['KeyId'],self.arn)
            return {'KeyId':self.arn,'SigningAlgorithm':ALGORITHM,
                'Signature':sign(json.loads(kwargs['Message']),self.f.private[OWNER_IDENTITY],self.f.directory.name)}
        self.kms.sign.side_effect=signing

    def run_sign(self,**overrides):
        args=dict(root=self.root,source_commit=self.f.source,approved_digest=digest(self.payload),
            kms=self.kms,sts=self.sts,now=self.f.now)
        args.update(overrides)
        return sign_proposal(self.payload,**args)

    def test_exact_proposal_uses_enrolled_owner_once_without_provider_or_reservation(self):
        result=self.run_sign()
        self.assertEqual(result['payload'],self.payload)
        self.kms.sign.assert_called_once()
        self.assertEqual(self.f.events,[])
        self.f.transport.send_once.assert_not_called()

    def test_changed_scope_even_with_matching_digest_cannot_sign(self):
        original=copy.deepcopy(self.payload)
        for key,value in [('approved_cap_micro_usd',1),('maximum_provider_calls',2),
                          ('source_commit','d'*40),('gate_authority',True),('expires_at',0)]:
            self.payload=copy.deepcopy(original); self.payload[key]=value
            with self.assertRaises(StateError): self.run_sign()
            self.kms.sign.assert_not_called()
        self.payload=original
        with self.assertRaises(StateError): self.run_sign(approved_digest='sha256:'+'0'*64)
        with self.assertRaises(StateError): self.run_sign(now=self.f.now.replace(tzinfo=None))
        self.kms.sign.assert_not_called()

    def test_root_and_changed_key_cannot_sign(self):
        self.sts.get_caller_identity.return_value['Arn']='arn:aws:iam::666730517561:root'
        with self.assertRaises(StateError): self.run_sign()
        self.kms.sign.assert_not_called()
        self.sts.get_caller_identity.return_value['Arn']='arn:aws:sts::666730517561:assumed-role/tims-factory-signing-owner/fixture'
        self.kms.get_public_key.return_value['KeyId']='different'
        with self.assertRaises(StateError): self.run_sign()
        self.kms.sign.assert_not_called()

    def test_uncertain_signing_is_sanitized_and_never_retried(self):
        self.kms.sign.side_effect=TimeoutError('PRIVATE')
        with self.assertRaises(StateError) as caught: self.run_sign()
        self.assertNotIn('PRIVATE',str(caught.exception))
        self.kms.sign.assert_called_once()


    def test_workflow_uses_existing_owner_identity_and_separate_disabled_gate(self):
        import yaml
        root=Path(__file__).resolve().parents[1]
        workflow=yaml.safe_load((root/'.github/workflows/factory-owner-signing.yml').read_text())
        job=workflow['jobs']['sign_google_free_allowance']
        self.assertIn("vars.FACTORY_GOOGLE_FREE_SIGNING_ENABLED == 'true'",job['if'])
        self.assertIn('github.run_attempt == 1',job['if'])
        self.assertEqual(job['environment'],'production')
        self.assertEqual(workflow['concurrency']['cancel-in-progress'],False)
        credentials=[s for s in job['steps'] if s.get('uses','').startswith('aws-actions/')]
        self.assertEqual(credentials[0]['with']['role-to-assume'],
            'arn:aws:iam::666730517561:role/tims-factory-signing-owner')
        commands='\n'.join(s.get('run','') for s in job['steps'])
        self.assertNotIn('${{',commands)
        self.assertNotIn('invoke',commands)


if __name__=='__main__': unittest.main()
