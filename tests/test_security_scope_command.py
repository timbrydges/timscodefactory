import base64
import copy
from dataclasses import asdict, replace
import json
from pathlib import Path
import unittest
from unittest.mock import Mock, patch

from scripts.sign_security_scope import sign_packet
from scripts.scope_dispatch_canary import sign
from factory_runtime.security_scope_policy import SecurityScopeSigner, IDENTITY
from factory_runtime.security_qa_provenance import ConsumedQAProvenance
from factory_runtime.review_signing import KEYS, ROLES
from factory_runtime.worker import digest
from factory_state.scope import canonical
from factory_state.signers import public_key_der
from factory_state.kms_signer import ALGORITHM
from factory_state.model import StateError
import test_security_scope_policy as fixtures


class ScopeCommandTests(unittest.TestCase):
    def setUp(self):
        self.f=fixtures.SecurityScopeTests();self.f.setUp();self.addCleanup(self.f.doCleanups)
        self.m=self.f.args['material'];self.mode='owner';self.calls=[]
        p=self.f.args['plan'];plan=asdict(p);plan['lease']['expires_at']=p.lease.expires_at.isoformat()
        qa=self.f.args['prerequisites']
        self.packet={'kind':'bounded_security004_scope_signing_plan','source_commit':self.m.binding.qa.source_commit,
            'role':'security','proof_run_id':123,'material_digest':digest(self.f.f.f.raw),
            'qa_binding':{**asdict(qa.qa_binding),'allowed_paths':list(qa.qa_binding.allowed_paths)},
            'qa_request':asdict(qa.request),'qa_result_digest':self.m.binding.qa_result_digest,
            'historical_signers':{'signers':[{'identity':'qa_engineer_service'}]},
            'plan':plan,'owner_signature_base64':''}
        patcher=patch('scripts.sign_security_scope.load_trusted_signers',return_value=self.f.keys)
        patcher.start();self.addCleanup(patcher.stop)

    def get_caller_identity(self):
        role=ROLES['owner'] if self.mode=='owner' else SecurityScopeSigner.role_bindings['spec']
        return {'Account':'666730517561','Arn':f'arn:aws:sts::666730517561:assumed-role/{role}/test'}

    def get_public_key(self, **kwargs):
        identity='tim_brydges' if self.mode=='owner' else IDENTITY
        return {'KeyId':kwargs['KeyId'],'KeySpec':'ECC_NIST_EDWARDS25519','KeyUsage':'SIGN_VERIFY',
            'SigningAlgorithms':[ALGORITHM],'PublicKey':public_key_der(self.f.keys[identity])}

    def sign(self, **kwargs):
        identity='tim_brydges' if self.mode=='owner' else IDENTITY
        self.calls.append(kwargs['KeyId'])
        return {'KeyId':kwargs['KeyId'],'SigningAlgorithm':ALGORITHM,
            'Signature':sign(json.loads(kwargs['Message']),self.f.private[identity],self.f.temp.name)}

    def run_sign(self, packet=None):
        p=packet or self.packet
        return sign_packet(p,approved_digest=digest(canonical(p)),source_commit=self.m.binding.qa.source_commit,
            mode=self.mode,kms=self,sts=self,states=self.f.states,ledger=Mock(),
            clock=lambda:self.f.now,importer=lambda *a,**k:self.f.f.f.raw)

    def test_isolated_owner_then_independent_review_checks_qa(self):
        owner=self.run_sign();self.packet['owner_signature_base64']=owner['signature_base64'];self.mode='spec'
        with patch.object(ConsumedQAProvenance,'__call__',return_value=True) as qa:
            result=self.run_sign();self.assertTrue(qa.called)
        self.assertEqual(result['payload']['reviewer_identity'],IDENTITY)
        self.assertEqual(self.calls,[KEYS['owner'],SecurityScopeSigner.key_bindings['spec']])

    def test_unconsumed_qa_and_changed_state_block_review(self):
        owner=self.run_sign();self.packet['owner_signature_base64']=owner['signature_base64'];self.mode='spec'
        with patch.object(ConsumedQAProvenance,'__call__',return_value=False):
            with self.assertRaises(StateError):self.run_sign()
        self.f.states.load_state.return_value=replace(self.f.states.load_state.return_value,version=8)
        with self.assertRaises(StateError):self.run_sign()
        self.assertEqual(len(self.calls),1)

    def test_historical_keys_cannot_supply_current_owner(self):
        p=copy.deepcopy(self.packet);p['historical_signers']['signers'].append({'identity':'tim_brydges'})
        with self.assertRaises(StateError):self.run_sign(p)
        self.assertEqual(self.calls,[])

    def test_substitution_or_forged_owner_prevents_review(self):
        for field,value in [('role','qa'),('qa_result_digest',digest(b'other')),('proof_run_id',True)]:
            p={**self.packet,field:value}
            with self.assertRaises(StateError):self.run_sign(p)
        self.mode='spec';self.packet['owner_signature_base64']=base64.b64encode(b'x'*64).decode()
        with self.assertRaises(StateError):self.run_sign()
        self.assertEqual(self.calls,[])

    def test_manual_workflows_preserve_custody_and_no_retry(self):
        import yaml
        root=Path(__file__).resolve().parents[1]
        for filename,role,command in (
                ('owner-signing','owner','sign_security_allowance.py'),
                ('owner-scope-signing','owner','sign_security_scope.py'),
                ('spec-scope-signing','spec-reviewer','sign_security_scope.py')):
            doc=yaml.load((root/'.github/workflows'/('factory-security-'+filename+'.yml')).read_text(),Loader=yaml.BaseLoader)
            self.assertEqual(set(doc['on']),{'workflow_dispatch'})
            job=doc['jobs']['sign']
            for guard in ("github.ref == 'refs/heads/main'","github.actor_id == '214414801'",'github.run_attempt == 1'):
                self.assertIn(guard,job['if'])
            self.assertEqual(job['environment'],'production')
            aws=[s for s in job['steps'] if s.get('uses','').startswith('aws-actions/')][0]
            self.assertEqual(aws['with']['role-to-assume'],'arn:aws:iam::666730517561:role/tims-factory-signing-'+role)
            self.assertEqual(aws['with']['disable-retry'],'true')
            self.assertEqual(sum(command in s.get('run','') for s in job['steps']),1)
