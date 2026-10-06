import base64
import copy
import json
import unittest
from unittest.mock import Mock, patch
from factory_state.model import OWNER_IDENTITY, StateError
from factory_state.scope import canonical
from factory_runtime.handoff004_packets import digest
from factory_runtime.handoff004_workflow import prepare_pricing
from factory_runtime.handoff004_entrypoint import load_activation
from sign_handoff004_allowance import validate_plan, sign, material, input_plan
from test_handoff004_entrypoint import HandoffEntrypointTests


class HandoffOwnerSigningTests(unittest.TestCase):
    def setUp(self):
        self.fixture = HandoffEntrypointTests(); self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.root = self.fixture.root; self.now = self.fixture.fixture.now
        doc = copy.deepcopy(self.fixture.doc)
        self.evidence = {'pricing': {'kind': 'synthetic'}, 'readiness': {'kind': 'synthetic'}}
        doc['qualification']['evidence_digest'] = digest(self.evidence['pricing'])
        doc['readiness']['evidence_digest'] = digest(self.evidence['readiness'])
        for field in ('qualification', 'readiness'):
            doc[field]['expires_at'] = int(self.now.timestamp())+600
        price = prepare_pricing(self.root, role='builder', source_commit='a'*40, qualification=doc['qualification'])
        doc['allowance']['payload'].update(pricing_digest=digest(price), readiness_digest=digest(doc['readiness']),
            expires_at=int(self.now.timestamp())+600)
        doc['allowance']['signature'] = ''
        self.plan = {'kind': 'handoff004_owner_signing_plan', 'activation': doc, 'evidence': self.evidence}
        registry = self.root/'factory/profiles/scope-signers.json'
        registry.parent.mkdir(parents=True, exist_ok=True); registry.write_bytes(canonical(doc['signer_registry']))

    def validate(self, plan=None):
        plan = self.plan if plan is None else plan
        return validate_plan(plan, root=self.root, approved_digest=digest(plan), source_commit='a'*40, now=self.now)

    def test_unsigned_preparation_never_passes_normal_runtime_verification(self):
        self.validate()
        with self.assertRaises(StateError): material(self.plan['activation'], self.root, self.now, unsigned=False)

    def test_source_enrollment_budget_and_evidence_substitution_rejected(self):
        mutations = [lambda p:p['activation'].update(source_commit='b'*40),
            lambda p:p['activation']['allowance']['payload'].update(approved_cap_micro_usd=500000),
            lambda p:p['activation']['signer_registry']['signers'][0].update(revoked=True),
            lambda p:p['evidence']['pricing'].update(kind='changed')]
        for mutate in mutations:
            plan = copy.deepcopy(self.plan); mutate(plan)
            with self.assertRaises(StateError): self.validate(plan)

    def test_real_signature_checked_after_exactly_one_signing_call(self):
        pem = self.fixture.fixture.keys[OWNER_IDENTITY]
        kms = Mock(); sts = Mock(); binding = {'key_arn':'synthetic-key','fingerprint':'synthetic-fingerprint'}
        def response(**args):
            return {'KeyId':binding['key_arn'],'SigningAlgorithm':args['SigningAlgorithm'],
                'Signature':self.fixture.fixture.private[OWNER_IDENTITY].sign(args['Message'])}
        kms.sign.side_effect = response
        with patch('sign_handoff004_allowance.EnrolledKmsReceiptSigner') as enrolled, \
                patch('sign_handoff004_allowance.KmsReceiptSigner') as signer, \
                patch('sign_handoff004_allowance.assert_role_identity'):
            enrolled.return_value._enrollment.return_value = (binding,pem)
            signer.return_value.pem = pem
            result = sign(self.plan, root=self.root, approved_digest=digest(self.plan), source_commit='a'*40,
                kms=kms, sts=sts, now=self.now)
        self.assertEqual(kms.sign.call_count,1)
        material(result,self.root,self.now,unsigned=False)

    def test_duplicate_and_oversized_public_input_rejected(self):
        for encoded in ('A'*65537, base64.b64encode(b'{"kind":1,"kind":2}').decode()):
            with self.assertRaises((ValueError,StateError)):input_plan(encoded)

    def test_owner_workflow_has_one_exact_identity_bound_job(self):
        import yaml
        from pathlib import Path
        w=yaml.safe_load((Path(__file__).resolve().parents[1]/'.github/workflows/factory-handoff004-owner-signing.yml').read_bytes())
        self.assertEqual(w['name'],'factory-owner-signing')
        self.assertEqual(set(w['jobs']),{'sign_handoff004_allowance'})
        self.assertEqual(len(w[True]['workflow_dispatch']['inputs']),2)
        guard=w['jobs']['sign_handoff004_allowance']['if']
        for value in ("github.ref == 'refs/heads/main'","github.actor_id == '214414801'","github.run_attempt == 1","inputs.handoff004_plan_digest != ''"):
            self.assertIn(value,guard)
