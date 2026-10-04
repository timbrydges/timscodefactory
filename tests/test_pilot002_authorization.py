import base64
import hashlib
import sys
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import Mock

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'src'))
from factory_runtime.pilot002_authorization import verify
from factory_runtime.pilot002_packets import builder_packet, review_packet, digest
from factory_runtime.pilot002_attempts import Pilot002AttemptStore
from factory_state.scope import canonical
from factory_state.model import OWNER_IDENTITY, StateError


class AllowanceTests(unittest.TestCase):
    def setUp(self):
        self.key=Ed25519PrivateKey.generate()
        self.keys={OWNER_IDENTITY:self.key.public_key().public_bytes(Encoding.PEM,PublicFormat.SubjectPublicKeyInfo)}
        self.now=datetime(2026,10,3,17,tzinfo=timezone.utc);self.epoch=int(self.now.timestamp())

    def context(self,role='builder'):
        builder=builder_packet(ROOT)
        raw=canonical({'task_id':builder['task_id'],'packet_digest':builder['packet_digest'],
            'files':{'fingerprint.py':'# candidate\n','tests/test_fingerprint.py':'# tests\n'}})
        extra={} if role=='builder' else {'builder_response':raw,'candidate_commit':'c'*40}
        packet=builder if role=='builder' else review_packet(ROOT,role=role,**extra)
        # Synthetic fixture, deliberately not a production provider request.
        body=canonical({'fixture_only_packet':packet})
        bindings={'role':role,'model_id':packet['model_id'],'task_id':packet['task_id'],
            'source_commit':'a'*40,'contract_digest':packet['contract_digest'],
            'packet_digest':packet['packet_digest'],'request_digest':'sha256:'+hashlib.sha256(body).hexdigest()}
        pricing={'kind':'pilot002_qualified_request_cost_bound',**bindings,'currency':'USD',
            'complete_request_bound_qualified':True,'maximum_cost_micro_usd':240000,
            'issued_at':self.epoch,'expires_at':self.epoch+3600,'evidence_digest':'sha256:'+'d'*64}
        ready={'kind':'pilot002_provider_readiness',**bindings,'credential_route_verified':True,
            'model_access_verified':True,'repository_binding_verified':True,
            'issued_at':self.epoch,'expires_at':self.epoch+1800,'evidence_digest':'sha256:'+'e'*64}
        payload={'kind':'pilot002_exact_request_allowance','owner_identity':OWNER_IDENTITY,
            **bindings,'pricing_digest':digest(pricing),'readiness_digest':digest(ready),
            'reserved_micro_usd':250000,'approved_cap_micro_usd':250000,'maximum_provider_calls':1,
            'retries':0,'task_state_writes':0,'gate_authority':False,'production_release_authorized':False,
            'issued_at':self.epoch,'expires_at':self.epoch+900}
        args=dict(root=ROOT,role=role,request_bytes=body,source_commit='a'*40,pricing=pricing,
            readiness=ready,trusted_keys=self.keys,now=self.now,**extra)
        return payload,args

    def sign(self,payload,key=None):
        return {'payload':payload,'signature':base64.b64encode((key or self.key).sign(canonical(payload))).decode()}

    def test_each_role_verifies_and_produces_exact_claim_arguments(self):
        for role in ('builder','inspector','qa'):
            payload,args=self.context(role)
            result=verify(self.sign(payload),**args)
            self.assertEqual(result['role'],role)
            self.assertEqual(result['approval_digest'],digest(payload))
            db=Mock();Pilot002AttemptStore(db).begin(**result)
            self.assertEqual(db.put_item.call_args.kwargs['Item']['reserved_micro_usd'],{'N':'250000'})

    def first_generation(self,role='builder'):
        payload,args=self.context(role)
        args['readiness'].update(kind='pilot002_builder_first_generation_readiness',model_access_verified=False,
            model_metadata_verified=True,first_generation_failure_risk_accepted=True)
        payload['readiness_digest']=digest(args['readiness'])
        return payload,args

    def test_first_builder_generation_requires_exact_owner_bound_acceptance(self):
        payload,args=self.first_generation()
        result=verify(self.sign(payload),**args)
        self.assertEqual(result['role'],'builder')
        self.assertEqual(payload['maximum_provider_calls'],1);self.assertEqual(payload['retries'],0)
        self.assertEqual(payload['reserved_micro_usd'],250000)
        self.assertFalse(args['readiness']['model_access_verified'])

    def test_first_generation_cannot_substitute_for_existing_signed_readiness(self):
        payload,args=self.context();envelope=self.sign(payload)
        _,new_args=self.first_generation()
        with self.assertRaises(StateError):verify(envelope,**new_args)

    def test_first_generation_rejects_missing_or_false_acceptance_and_claimed_access(self):
        for field,value in [('first_generation_failure_risk_accepted',False),('model_metadata_verified',False),
                            ('model_access_verified',True),('credential_route_verified',False),
                            ('repository_binding_verified',False),('first_generation_failure_risk_accepted',1)]:
            payload,args=self.first_generation();args['readiness'][field]=value
            payload['readiness_digest']=digest(args['readiness'])
            with self.assertRaises(StateError):verify(self.sign(payload),**args)
        payload,args=self.first_generation();del args['readiness']['first_generation_failure_risk_accepted']
        payload['readiness_digest']=digest(args['readiness'])
        with self.assertRaises(StateError):verify(self.sign(payload),**args)

    def test_first_generation_is_not_available_to_inspector_or_qa(self):
        for role in ('inspector','qa'):
            payload,args=self.first_generation(role)
            with self.assertRaises(StateError):verify(self.sign(payload),**args)

    def reviewer_first_generation(self,role):
        payload,args=self.context(role)
        args['readiness'].update(kind='pilot002_reviewer_first_generation_readiness',model_access_verified=False,
            model_metadata_verified=True,input_token_count_verified=True,first_generation_failure_risk_accepted=True)
        payload['readiness_digest']=digest(args['readiness'])
        return payload,args

    def test_reviewer_first_attempt_requires_own_signed_readiness(self):
        for role in ('inspector','qa'):
            payload,args=self.reviewer_first_generation(role)
            self.assertEqual(verify(self.sign(payload),**args)['role'],role)
            old,_=self.context(role)
            with self.assertRaises(StateError):verify(self.sign(old),**args)
            with self.assertRaises(StateError):verify(self.sign(payload),**{**args,'candidate_commit':'f'*40})

    def test_reviewer_exception_cannot_apply_to_builder(self):
        payload,args=self.reviewer_first_generation('builder')
        with self.assertRaises(StateError):verify(self.sign(payload),**args)

    def test_reviewer_evidence_and_risk_acceptance_fail_closed(self):
        for role in ('inspector','qa'):
            for field,value in [('model_access_verified',True),('model_metadata_verified',False),
                    ('input_token_count_verified',False),('input_token_count_verified',1),
                    ('first_generation_failure_risk_accepted',False),('credential_route_verified',False),
                    ('repository_binding_verified',False),('expires_at',self.epoch)]:
                payload,args=self.reviewer_first_generation(role);args['readiness'][field]=value
                payload['readiness_digest']=digest(args['readiness'])
                with self.subTest(role=role,field=field),self.assertRaises(StateError):verify(self.sign(payload),**args)
            payload,args=self.reviewer_first_generation(role);del args['readiness']['input_token_count_verified']
            payload['readiness_digest']=digest(args['readiness'])
            with self.assertRaises(StateError):verify(self.sign(payload),**args)

    def test_reviewer_exception_preserves_caps_and_no_retry(self):
        for role in ('inspector','qa'):
            for field,value in [('maximum_provider_calls',2),('retries',1),('approved_cap_micro_usd',250001),
                    ('reserved_micro_usd',0),('task_state_writes',1),('gate_authority',True)]:
                payload,args=self.reviewer_first_generation(role);payload[field]=value
                with self.subTest(role=role,field=field),self.assertRaises(StateError):verify(self.sign(payload),**args)

    def test_first_generation_still_rejects_staleness_and_expanded_allowance(self):
        payload,args=self.first_generation();args['readiness']['expires_at']=self.epoch
        payload['readiness_digest']=digest(args['readiness'])
        with self.assertRaises(StateError):verify(self.sign(payload),**args)
        for field,value in [('maximum_provider_calls',2),('retries',1),('approved_cap_micro_usd',250001)]:
            payload,args=self.first_generation();payload[field]=value
            with self.assertRaises(StateError):verify(self.sign(payload),**args)

    def test_valid_signature_cannot_expand_scope(self):
        for field,value in [('role','qa'),('maximum_provider_calls',2),('retries',1),('task_state_writes',1),
                            ('gate_authority',True),('production_release_authorized',True),
                            ('approved_cap_micro_usd',250001),('reserved_micro_usd',1),
                            ('maximum_provider_calls',True),('extra','anything')]:
            payload,args=self.context();payload[field]=value
            with self.subTest(field=field),self.assertRaises(StateError):verify(self.sign(payload),**args)

    def test_wrong_signer_and_tampered_signature_rejected(self):
        payload,args=self.context()
        with self.assertRaises(StateError):verify(self.sign(payload,Ed25519PrivateKey.generate()),**args)
        envelope=self.sign(payload);envelope['signature']='A'*88
        with self.assertRaises(StateError):verify(envelope,**args)
        with self.assertRaises(StateError):verify(self.sign(payload),**{**args,'trusted_keys':{}})

    def test_request_source_candidate_and_role_changes_rejected(self):
        payload,args=self.context('qa');signed=self.sign(payload)
        for change in ({'request_bytes':args['request_bytes']+b' '},{'source_commit':'b'*40},
                       {'candidate_commit':'d'*40},{'role':'inspector'}):
            with self.subTest(change=change),self.assertRaises(StateError):verify(signed,**{**args,**change})

    def test_signed_allowance_expiry_future_and_lifetime_bound(self):
        for change in ({'expires_at':self.epoch},{'issued_at':self.epoch+1},
                       {'issued_at':self.epoch-3000,'expires_at':self.epoch+900},
                       {'expires_at':self.epoch+1801}):
            payload,args=self.context();payload.update(change)
            with self.subTest(change=change),self.assertRaises(StateError):verify(self.sign(payload),**args)

    def test_unqualified_stale_free_or_over_cap_price_rejected(self):
        for change in ({'maximum_cost_micro_usd':250001},{'maximum_cost_micro_usd':0},
                       {'maximum_cost_micro_usd':True},{'complete_request_bound_qualified':False},
                       {'expires_at':self.epoch},{'expires_at':self.epoch+86401},
                       {'evidence_digest':'missing'}):
            payload,args=self.context();args['pricing'].update(change);payload['pricing_digest']=digest(args['pricing'])
            with self.subTest(change=change),self.assertRaises(StateError):verify(self.sign(payload),**args)

    def test_signed_stale_or_unverified_readiness_rejected(self):
        for change in ({'repository_binding_verified':False},{'credential_route_verified':False},
                       {'model_access_verified':False},{'model_access_verified':1},
                       {'expires_at':self.epoch},{'expires_at':self.epoch+3601}):
            payload,args=self.context();args['readiness'].update(change);payload['readiness_digest']=digest(args['readiness'])
            with self.subTest(change=change),self.assertRaises(StateError):verify(self.sign(payload),**args)

    def test_changed_trusted_evidence_invalidates_prior_signature(self):
        payload,args=self.context();signed=self.sign(payload)
        args['pricing']['maximum_cost_micro_usd']-=1
        with self.assertRaises(StateError):verify(signed,**args)

    def test_invalid_context_and_envelope_rejected(self):
        payload,args=self.context();signed=self.sign(payload)
        for change in ({'now':self.now.replace(tzinfo=None)},{'source_commit':'main'},
                       {'request_bytes':b''},{'request_bytes':b'x'*65537},{'builder_response':b'ignored'}):
            with self.subTest(change=change),self.assertRaises(StateError):verify(signed,**{**args,**change})
        for envelope in ({},payload,{**signed,'trusted_keys':self.keys}):
            with self.assertRaises(StateError):verify(envelope,**args)


if __name__=='__main__':unittest.main()
