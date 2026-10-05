import base64
import copy
import hashlib
import json
from datetime import datetime, timezone, timedelta
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'scripts'))
import sign_pilot002_reviewer_allowance as p
from factory_runtime.pilot002_packets import review_packet


class ReviewerSigningTests(unittest.TestCase):
    def setUp(self):
        self.now=datetime(2026,10,4,3,30,tzinfo=timezone.utc)

    def plan(self,role):
        # Synthetic prices/readiness for offline tests, never live qualifications.
        raw=(ROOT/'tests/pilot002_reviewer_builder_context.json').read_bytes()
        bound={'role':role,'builder_response':raw,'candidate_commit':p.CANDIDATE}
        packet=review_packet(ROOT,**bound)
        request=p.request_bytes(ROOT,**bound)
        epoch=int(self.now.timestamp());expiry=epoch+(300 if role=='qa' else 1800)
        source=p.QA_SOURCE if role=='qa' else p.SOURCE
        bindings={'role':role,'source_commit':source,'model_id':packet['model_id'],
            'task_id':packet['task_id'],'contract_digest':packet['contract_digest'],
            'packet_digest':packet['packet_digest'],'request_digest':'sha256:'+hashlib.sha256(request).hexdigest()}
        q={'kind':'pilot002_provider_rate_qualification',**bindings,'currency':'USD',
            'complete_request_bound_qualified':True,'combined_output_bound_qualified':True,
            'standard_text_only_no_cache_rates':True,'input_token_bound':32768,'output_token_bound':4096,
            'input_micro_usd_per_million':3000000,'output_micro_usd_per_million':15000000,
            'issued_at':epoch,'expires_at':expiry,'evidence_digest':p.digest({'fixture_only':True})}
        if role=='qa':
            q.update(kind='pilot002_google_free_tier_qualification',complete_request_bound_qualified=False,
                combined_output_bound_qualified=False,input_micro_usd_per_million=0,output_micro_usd_per_million=0,
                billing_observation={'google_project':'gen-lang-client-0247455615','billing_account_linked':False,
                    'credential_project_verified':True,'data_scope':'public-synthetic-fixtures-only',
                    'free_tier_data_use_accepted':True,'observed_at':epoch,'evidence_digest':p.digest({'fixture_only':True})})
        evidence={'fixture_only':True}
        readiness={'kind':'pilot002_reviewer_first_generation_readiness',**bindings,
            'credential_route_verified':True,'repository_binding_verified':True,'model_access_verified':False,
            'model_metadata_verified':True,'input_token_count_verified':True,'first_generation_failure_risk_accepted':True,
            'issued_at':epoch,'expires_at':expiry,'evidence_digest':p.digest(evidence)}
        registry=json.loads((ROOT/'factory/profiles/scope-signers.json').read_bytes())
        registry['signers']=[v for v in registry['signers'] if v['identity']=='tim_brydges']
        doc={'schema_version':'1.0','role':role,'source_commit':source,'qualification':q,'readiness':readiness,
            'signer_registry':registry,'credential':{'kind':'lambda_execution_role'} if role=='inspector' else copy.deepcopy(p.GOOGLE_ROUTE),
            'builder_response_base64':base64.b64encode(raw).decode(),'candidate_commit':p.CANDIDATE}
        price=p.Pilot002Adapter(ROOT,**bound,source_commit=source,qualification=q,clock=lambda:self.now).pricing
        payload={'kind':'pilot002_exact_request_allowance','owner_identity':'tim_brydges',**bindings,
            'pricing_digest':p.digest(price),'readiness_digest':p.digest(readiness),'reserved_micro_usd':250000,
            'approved_cap_micro_usd':250000,'maximum_provider_calls':1,'retries':0,'task_state_writes':0,
            'gate_authority':False,'production_release_authorized':False,'issued_at':epoch,'expires_at':expiry}
        return {'status':'UNSIGNED_REVIEW_CANDIDATE_NOT_AUTHORIZATION','activation':doc,
            'activation_sha256':hashlib.sha256(p.canonical(doc)).hexdigest(),'pricing':price,
            'allowance_payload':payload,'allowance_payload_digest':p.digest(payload),'evidence':evidence,
            'kms_key_arn':'arn:aws:kms:ca-central-1:666730517561:key/4cdc8470-77f4-4c5a-a772-7b379f34fbbb'}

    def validate(self,plan,role,**kwargs):
        return p.validate_plan(plan,root=ROOT,role=role,approved_digest=kwargs.get('digest',p.digest(plan)),now=kwargs.get('now',self.now))

    def test_both_counted_requests_validate_offline(self):
        for role in p.REQUESTS:
            plan=self.plan(role)
            self.assertEqual(self.validate(plan,role),plan['allowance_payload'])

    def test_expiry_digest_role_candidate_and_scope_rejected_before_kms(self):
        for role in p.REQUESTS:
            original=self.plan(role)
            changes=[lambda x:x['activation'].update(source_commit='0'*40),
                lambda x:x['activation'].update(candidate_commit='0'*40),
                lambda x:x['activation'].update(role='builder'),
                lambda x:x['evidence'].update(changed=True)]
            changes += [lambda x,k=k,v=v:x['allowance_payload'].update({k:v}) for k,v in
                [('approved_cap_micro_usd',250001),('reserved_micro_usd',0),('maximum_provider_calls',2),
                 ('retries',1),('task_state_writes',1),('gate_authority',True),('production_release_authorized',True)]]
            for change in changes:
                plan=copy.deepcopy(original);change(plan);kms=Mock()
                with self.assertRaises(Exception):
                    p.sign(plan,root=ROOT,role=role,approved_digest=p.digest(plan),kms=kms,sts=Mock(),now=self.now)
                self.assertEqual(kms.mock_calls,[])
            with self.assertRaises(Exception):self.validate(original,role,digest='sha256:'+'0'*64)
            with self.assertRaises(Exception):self.validate(original,role,now=self.now+timedelta(hours=1))

    def test_changed_request_even_with_recomputed_activation_is_rejected(self):
        plan=self.plan('inspector')
        raw=json.loads(base64.b64decode(plan['activation']['builder_response_base64']))
        raw['files']['fingerprint.py']+='\n# unreviewed\n'
        plan['activation']['builder_response_base64']=base64.b64encode(p.canonical(raw)).decode()
        plan['activation_sha256']=hashlib.sha256(p.canonical(plan['activation'])).hexdigest()
        with self.assertRaises(Exception):self.validate(plan,'inspector')

    def test_billing_and_credential_changes_are_rejected(self):
        for field,value in [('version_id','a'*32),('json_key','api_key')]:
            plan=self.plan('qa');plan['activation']['credential'][field]=value
            with self.assertRaises(Exception):self.validate(plan,'qa')
        plan=self.plan('qa');plan['activation']['qualification']['billing_observation']['billing_account_linked']=True
        with self.assertRaises(Exception):self.validate(plan,'qa')

    def test_owner_signature_is_verified_once_and_uncertain_call_not_retried(self):
        for role in p.REQUESTS:
            plan=self.plan(role);key=Ed25519PrivateKey.generate()
            pem=key.public_key().public_bytes(Encoding.PEM,PublicFormat.SubjectPublicKeyInfo)
            binding={'key_arn':plan['kms_key_arn'],'fingerprint':'fixture'}
            enrollment=Mock();enrollment._enrollment.return_value=(binding,pem)
            sts=Mock();sts.get_caller_identity.return_value={'Account':'666730517561',
                'Arn':'arn:aws:sts::666730517561:assumed-role/tims-factory-signing-owner/test'}
            with patch.object(p,'EnrolledKmsReceiptSigner',return_value=enrollment),patch.object(p,'KmsReceiptSigner',return_value=Mock(pem=pem)):
                for failure in (False,True):
                    kms=Mock()
                    kms.sign.side_effect=TimeoutError('PRIVATE') if failure else lambda **kw:{
                        'KeyId':binding['key_arn'],'SigningAlgorithm':p.ALGORITHM,'Signature':key.sign(kw['Message'])}
                    if failure:
                        with self.assertRaisesRegex(p.StateError,'without retry') as caught:
                            p.sign(plan,root=ROOT,role=role,approved_digest=p.digest(plan),kms=kms,sts=sts,now=self.now)
                        self.assertNotIn('PRIVATE',str(caught.exception))
                    else:
                        result=p.sign(plan,root=ROOT,role=role,approved_digest=p.digest(plan),kms=kms,sts=sts,now=self.now)
                        key.public_key().verify(base64.b64decode(result['signature']),p.canonical(result['payload']))
                    self.assertEqual(kms.sign.call_count,1)

    def test_root_cannot_sign(self):
        plan=self.plan('inspector');kms=Mock();sts=Mock()
        sts.get_caller_identity.return_value={'Account':'666730517561','Arn':'arn:aws:iam::666730517561:root'}
        with self.assertRaises(Exception):p.sign(plan,root=ROOT,role='inspector',approved_digest=p.digest(plan),kms=kms,sts=sts,now=self.now)
        kms.sign.assert_not_called()

    def test_plan_size_and_duplicate_keys_fail_closed(self):
        with tempfile.TemporaryDirectory() as d:
            path=Path(d)/'plan.json'
            for raw in (b' '*131073,b'{"role":"qa","role":"inspector"}'):
                path.write_bytes(raw)
                with self.assertRaises(Exception):p.read_plan(path)

    def test_fresh_qa_input_preserves_exact_plan_and_expiry(self):
        plan=self.plan('qa')
        encoded=base64.b64encode(p.canonical(plan)).decode()
        decoded=p.input_plan('qa',encoded)
        self.assertEqual(decoded,plan)
        self.validate(decoded,'qa')
        with self.assertRaises(p.StateError):
            self.validate(decoded,'qa',now=self.now+timedelta(seconds=300))
        with self.assertRaises(p.StateError):
            self.validate(decoded,'qa',digest='sha256:'+'0'*64)

    def test_runtime_plan_cannot_reach_inspector_or_other_roles(self):
        encoded=base64.b64encode(p.canonical(self.plan('qa'))).decode()
        for role in ('inspector','builder','none'):
            with self.assertRaises(p.StateError):p.input_plan(role,encoded)
        self.assertEqual(p.input_plan('inspector','')['activation']['role'],'inspector')

    def test_malformed_oversized_and_duplicate_runtime_data_rejected(self):
        for encoded in ('','!', 'A'*65537,base64.b64encode(b'[]').decode(),
                base64.b64encode(b'{"role":"qa","role":"qa"}').decode()):
            with self.assertRaises(p.StateError):p.input_plan('qa',encoded)

    def test_workflow_is_owner_only_and_mutually_exclusive(self):
        import yaml
        workflow=yaml.safe_load((ROOT/'.github/workflows/factory-owner-signing.yml').read_text())
        jobs=workflow['jobs'];job=jobs['sign_pilot002_reviewer_allowance']
        for guard in ('github.run_attempt == 1',"github.actor_id == '214414801'","github.ref == 'refs/heads/main'",
                "inputs.pilot002_builder_plan_digest == ''","inputs.receipt_iam_canary == false"):
            self.assertIn(guard,job['if'])
        self.assertEqual(job['environment'],'production')
        for name,value in jobs.items():
            if name!='sign_pilot002_reviewer_allowance':
                self.assertIn("inputs.pilot002_qa_plan_base64 == ''",value['if'])
                self.assertIn("inputs.pilot002_reviewer_plan_digest == ''",value['if'])
                self.assertIn("inputs.pilot002_reviewer_role == 'none'",value['if'])
        commands='\n'.join(step.get('run','') for step in job['steps'])
        self.assertNotIn('${{',commands);self.assertNotIn('invoke',commands)
        self.assertIn("inputs.pilot002_reviewer_role == 'qa' && inputs.pilot002_qa_plan_base64 != ''",job['if'])
        self.assertIn("inputs.pilot002_reviewer_role == 'inspector' && inputs.pilot002_qa_plan_base64 == ''",job['if'])
        self.assertEqual(job['env']['PILOT002_QA_PLAN_BASE64'],'${{ inputs.pilot002_qa_plan_base64 }}')
        credentials=[s for s in job['steps'] if s.get('uses','').startswith('aws-actions/')]
        self.assertEqual(credentials[0]['with']['role-to-assume'],'arn:aws:iam::666730517561:role/tims-factory-signing-owner')


if __name__=='__main__':unittest.main()
