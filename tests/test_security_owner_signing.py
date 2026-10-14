import base64
import copy
from datetime import timedelta
from dataclasses import asdict
from factory_runtime.security_material import PinnedSecurityMaterial
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from scripts.sign_security_allowance import decode, validate_plan, sign_plan
from factory_state.model import StateError
from factory_state.scope import canonical
from factory_runtime.worker import digest
from test_review_material import MaterialTests
from test_security_provider_scope import fixture


class SecurityOwnerPlanTests(unittest.TestCase):
    def setUp(self):
        self.f=MaterialTests();self.f.setUp();self.addCleanup(self.f.doCleanups)
        self.now=self.f.f.now
        self.qa=self.f.load().binding('qa')
        self.qa_result=digest(b'fixture consumed signed QA')
        self.material=PinnedSecurityMaterial.load(self.f.raw,expected_digest=digest(self.f.raw),
            deployed_commit=self.f.f.commit,qa_binding=self.qa,qa_result_digest=self.qa_result,clock=lambda:self.now)
        scope=self.material.prepared().scope
        _,price,ready,payload=fixture()
        times={'issued_at':int(self.now.timestamp())-1,'expires_at':int(self.now.timestamp())+600}
        self.evidence={'pricing':{'fixture':'reviewed quote'},'readiness':{'fixture':'reviewed route'}}
        price.update(scope.bindings(),**times,evidence_digest=digest(canonical(self.evidence['pricing'])))
        ready.update(scope.bindings(),**times,evidence_digest=digest(canonical(self.evidence['readiness'])))
        payload.update(scope.bindings(),**times,pricing_digest=digest(canonical(price)),readiness_digest=digest(canonical(ready)))
        self.plan={'kind':'bounded_security004_owner_signing_plan','source_commit':self.material.binding.qa.source_commit,
            'role':'security','proof_run_id':123,'material_digest':digest(self.f.raw),
            'qa_binding':{**asdict(self.qa),'allowed_paths':list(self.qa.allowed_paths)},
            'qa_result_digest':self.qa_result,'pricing':price,'readiness':ready,'allowance':payload,'evidence':self.evidence}
        self.importer=Mock(return_value=self.f.raw)

    def validate(self,plan=None,**changes):
        p=self.plan if plan is None else plan
        kw={'approved_digest':digest(canonical(p)),'source_commit':self.material.binding.qa.source_commit,
            'clock':lambda:self.now,'importer':self.importer}
        kw.update(changes)
        return validate_plan(p,**kw)

    def test_valid_reviewed_plan_reimports_material(self):
        self.assertEqual(self.validate(),self.material.prepared().scope)
        self.assertEqual(self.importer.call_args.args,(self.material.binding.qa.source_commit,123))

    def test_modified_plan_source_role_and_evidence_block(self):
        for changes in ({'source_commit':'a'*40},{'role':'planner'},{'proof_run_id':True},
                        {'kind':'historical-allowance'},{'material_digest':digest(b'wrong')},
                        {'evidence':{'pricing':{},'readiness':{}}}):
            with self.subTest(changes=changes),self.assertRaises(StateError):self.validate({**self.plan,**changes})
        with self.assertRaises(StateError):self.validate(approved_digest=digest(b'not approved'))
        p=copy.deepcopy(self.plan);p['evidence']['pricing']['fixture']='substituted'
        with self.assertRaises(StateError):self.validate(p)

    def test_stale_material_expanded_budget_and_retries_rejected(self):
        with self.assertRaises(StateError):self.validate(clock=lambda:self.now+timedelta(hours=2))
        for change in ({'retries':1},{'reserved_micro_usd':250001},{'maximum_provider_calls':2},
                       {'aggregate_ceiling_micro_usd':3250001},{'expires_at':int(self.now.timestamp())+299}):
            p=copy.deepcopy(self.plan);p['allowance'].update(change)
            with self.subTest(change=change),self.assertRaises(StateError):self.validate(p)

    def test_import_failure_prevents_signing(self):
        self.importer.side_effect=StateError('changed main or failed Docker job')
        with patch('scripts.sign_security_allowance.SecurityAllowanceSigner') as signer:
            with self.assertRaises(StateError):
                sign_plan(self.plan,approved_digest=digest(canonical(self.plan)),source_commit=self.material.binding.qa.source_commit,
                    kms=Mock(),sts=Mock(),clock=lambda:self.now,importer=self.importer)
            signer.assert_not_called()

    def test_canonical_bounded_decode(self):
        self.assertEqual(decode(base64.b64encode(canonical(self.plan)).decode()),self.plan)
        for raw in (canonical(self.plan)+b' ',b'{"x":1,"x":2}',b'x'*49153):
            with self.assertRaises(StateError):decode(base64.b64encode(raw).decode())
        for encoded in ('', '!', 'x'*65537):
            with self.assertRaises(StateError):decode(encoded)

    def test_qa_substitution_and_unverified_route_block_before_signer(self):
        for change in ('candidate','receipt','role','shape','route'):
            p=copy.deepcopy(self.plan)
            if change=='candidate':p['qa_binding']['candidate_commit']='f'*40
            if change=='receipt':p['qa_result_digest']=digest(b'other receipt')
            if change=='role':p['qa_binding']['role_id']='independent_inspector'
            if change=='shape':p['qa_binding']['unexpected']=True
            if change=='route':
                p['readiness']['credential_route_verified']=False
                p['allowance']['readiness_digest']=digest(canonical(p['readiness']))
            with self.subTest(change=change),patch('scripts.sign_security_allowance.SecurityAllowanceSigner') as signer:
                with self.assertRaises(StateError):
                    sign_plan(p,approved_digest=digest(canonical(p)),source_commit=self.material.binding.qa.source_commit,
                        kms=Mock(),sts=Mock(),clock=lambda:self.now,importer=self.importer)
                signer.assert_not_called()

    def test_valid_plan_uses_security_adapter_once(self):
        with patch('scripts.sign_security_allowance.SecurityAllowanceSigner') as signer:
            signer.return_value.sign.return_value=b'x'*64
            result=sign_plan(self.plan,approved_digest=digest(canonical(self.plan)),
                source_commit=self.material.binding.qa.source_commit,kms=Mock(),sts=Mock(),
                clock=lambda:self.now,importer=self.importer)
            self.assertEqual(result['payload'],self.plan['allowance'])
            self.assertEqual(base64.b64decode(result['signature_base64']),b'x'*64)
            signer.return_value.sign.assert_called_once()
            self.assertEqual(signer.call_args.kwargs['scope'],self.material.prepared().scope)
