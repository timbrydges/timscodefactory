import base64
import copy
from dataclasses import asdict, replace
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from scripts.sign_bounded_review_scope import sign_packet
from scripts.scope_dispatch_canary import fixture_keys, sign
from factory_runtime.review_intake import prepare_intake
from factory_runtime.review_scope_policy import FACTORY,TASK,IDENTITY,ReviewScopeSigner
from factory_runtime.review_signing import KEYS,ROLES
from factory_runtime.worker import digest
from factory_state.model import TaskState,CONTROLLER_IDENTITY,StateError
from factory_state.kms_signer import ALGORITHM
from factory_state.signers import public_key_der
from factory_state.scope import canonical
import test_review_material as material_fixtures


class ScopeSigningTests(unittest.TestCase):
    def setUp(self):
        self.f=material_fixtures.MaterialTests();self.f.setUp();self.addCleanup(self.f.doCleanups)
        self.material=self.f.load();self.now=self.f.f.now
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.keys,self.private=fixture_keys(self.tmp.name,('tim_brydges',IDENTITY))
        self.state=TaskState(FACTORY,TASK,'IMPLEMENTATION',0,self.now,CONTROLLER_IDENTITY)
        self.states=Mock(load_state=Mock(side_effect=lambda *args:self.state))
        p=prepare_intake(material=self.material,role='builder',states=self.states,clock=lambda:self.now)
        plan=asdict(p);plan['lease']['expires_at']=p.lease.expires_at.isoformat()
        self.packet={'kind':'bounded_review002_scope_signing_plan','source_commit':self.material.source_commit,
            'role':'builder','proof_run_id':123,'material_digest':digest(self.f.raw),'plan':plan,'owner_signature_base64':''}
        self.mode='owner';self.calls=[]
        patcher=patch('scripts.sign_bounded_review_scope.load_trusted_signers',return_value=self.keys)
        patcher.start();self.addCleanup(patcher.stop)

    def get_caller_identity(self):
        role=ROLES['owner'] if self.mode=='owner' else ReviewScopeSigner.role_bindings['spec']
        return {'Account':'666730517561','Arn':'arn:aws:sts::666730517561:assumed-role/'+role+'/fixture'}

    def get_public_key(self,**kwargs):
        identity='tim_brydges' if self.mode=='owner' else IDENTITY
        return {'KeyId':kwargs['KeyId'],'KeySpec':'ECC_NIST_EDWARDS25519','KeyUsage':'SIGN_VERIFY',
            'SigningAlgorithms':[ALGORITHM],'PublicKey':public_key_der(self.keys[identity])}

    def sign(self,**kwargs):
        identity='tim_brydges' if self.mode=='owner' else IDENTITY
        self.calls.append(kwargs)
        return {'KeyId':kwargs['KeyId'],'SigningAlgorithm':ALGORITHM,
            'Signature':sign(json.loads(kwargs['Message']),self.private[identity],self.tmp.name)}

    def run_sign(self,packet=None):
        p=self.packet if packet is None else packet
        return sign_packet(p,approved_digest=digest(canonical(p)),
            source_commit=self.material.source_commit,mode=self.mode,kms=self,sts=self,states=self.states,
            clock=lambda:self.now,importer=lambda *a,**k:self.f.raw)

    def test_real_owner_then_independent_signature_only_for_current_stage(self):
        owner=self.run_sign();self.packet['owner_signature_base64']=owner['signature_base64'];self.mode='spec'
        review=self.run_sign()
        self.assertEqual(review['payload']['reviewer_identity'],IDENTITY)
        self.assertEqual([c['KeyId'] for c in self.calls],[KEYS['owner'],ReviewScopeSigner.key_bindings['spec']])
        self.assertEqual({c[0] for c in self.states.mock_calls},{'load_state'})

    def test_expanded_owner_capability_and_wrong_lease_block_before_kms(self):
        for field,value in [('stop_condition','release'),('required_evidence','canary'),('contract_digest',digest(b'other'))]:
            p=copy.deepcopy(self.packet);p['plan']['capability_payload'][field]=value
            with self.assertRaises(StateError):self.run_sign(p)
        p=copy.deepcopy(self.packet);p['plan']['lease']['lease_id']='another'
        with self.assertRaises(StateError):self.run_sign(p)
        self.assertEqual(self.calls,[])

    def test_forged_owner_or_changed_live_state_prevents_reviewer_sign(self):
        self.mode='spec';self.packet['owner_signature_base64']=base64.b64encode(b'x'*64).decode()
        with self.assertRaises(StateError):self.run_sign()
        self.mode='owner';self.packet['owner_signature_base64']='';owner=self.run_sign()
        self.packet['owner_signature_base64']=owner['signature_base64'];self.mode='spec'
        self.state=replace(self.state,state='INSPECTION',version=1)
        with self.assertRaises(StateError):self.run_sign()
        self.assertEqual(len(self.calls),1)

    def test_workflows_keep_isolated_signing_roles_and_no_retry(self):
        import yaml
        for mode,name in [('owner','factory-owner-signing'),('spec','factory-spec-reviewer-signing')]:
            path=Path(__file__).resolve().parents[1]/('.github/workflows/factory-bounded-'+mode+'-scope-signing.yml')
            doc=yaml.load(path.read_text(),Loader=yaml.BaseLoader);job=doc['jobs']['sign']
            self.assertEqual(doc['name'],name);self.assertIn('github.run_attempt == 1',job['if'])
            self.assertEqual(job['environment'],'production')
            aws=[x for x in job['steps'] if x.get('uses','').startswith('aws-actions/')][0]
            self.assertEqual(aws['with']['disable-retry'],'true')
            role=ROLES['owner'] if mode=='owner' else ReviewScopeSigner.role_bindings['spec']
            self.assertTrue(aws['with']['role-to-assume'].endswith('/'+role))
