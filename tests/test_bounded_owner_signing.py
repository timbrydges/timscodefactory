import base64
import copy
from datetime import timedelta
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from scripts.sign_bounded_review_allowance import decode, validate_plan, sign_plan
from factory_state.model import StateError
from factory_state.scope import canonical
from factory_runtime.worker import digest
from test_review_material import MaterialTests
from test_review_provider_scope import fixture


class OwnerPlanTests(unittest.TestCase):
    def setUp(self):
        self.f=MaterialTests();self.f.setUp();self.addCleanup(self.f.doCleanups)
        self.material=self.f.load();self.now=self.f.f.now
        scope=self.material.prepared('builder').scope
        _,price,ready,payload=fixture()
        times={'issued_at':int(self.now.timestamp())-1,'expires_at':int(self.now.timestamp())+600}
        self.evidence={'pricing':{'fixture':'reviewed quote'},'readiness':{'fixture':'reviewed route'}}
        price.update(scope.bindings(),**times,evidence_digest=digest(canonical(self.evidence['pricing'])))
        ready.update(scope.bindings(),**times,evidence_digest=digest(canonical(self.evidence['readiness'])))
        payload.update(scope.bindings(),**times,pricing_digest=digest(canonical(price)),readiness_digest=digest(canonical(ready)))
        self.plan={'kind':'bounded_review004_owner_signing_plan','source_commit':self.material.source_commit,
            'role':'builder','proof_run_id':123,'material_digest':digest(self.f.raw),
            'pricing':price,'readiness':ready,'allowance':payload,'evidence':self.evidence}
        self.importer=Mock(return_value=self.f.raw)

    def validate(self,plan=None,**changes):
        p=self.plan if plan is None else plan
        kw={'approved_digest':digest(canonical(p)),'source_commit':self.material.source_commit,
            'clock':lambda:self.now,'importer':self.importer}
        kw.update(changes)
        return validate_plan(p,**kw)

    def test_valid_reviewed_plan_reimports_material(self):
        self.assertEqual(self.validate(),self.material.prepared('builder').scope)
        self.assertEqual(self.importer.call_args.args,(self.material.source_commit,123))

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
        with patch('scripts.sign_bounded_review_allowance.ReviewAllowanceSigner') as signer:
            with self.assertRaises(StateError):
                sign_plan(self.plan,approved_digest=digest(canonical(self.plan)),source_commit=self.material.source_commit,
                    kms=Mock(),sts=Mock(),clock=lambda:self.now,importer=self.importer)
            signer.assert_not_called()

    def test_canonical_bounded_decode(self):
        self.assertEqual(decode(base64.b64encode(canonical(self.plan)).decode()),self.plan)
        for raw in (canonical(self.plan)+b' ',b'{"x":1,"x":2}',b'x'*49153):
            with self.assertRaises(StateError):decode(base64.b64encode(raw).decode())
        for encoded in ('', '!', 'x'*65537):
            with self.assertRaises(StateError):decode(encoded)

    def test_workflow_keeps_existing_owner_identity_and_first_attempt_gate(self):
        import yaml
        doc=yaml.load((Path(__file__).resolve().parents[1]/'.github/workflows/factory-bounded-owner-signing.yml').read_text(),Loader=yaml.BaseLoader)
        self.assertEqual(doc['name'],'factory-owner-signing')
        self.assertEqual(set(doc['on']),{'workflow_dispatch'})
        job=doc['jobs']['sign']
        for guard in ("github.ref == 'refs/heads/main'","github.actor_id == '214414801'",'github.run_attempt == 1'):
            self.assertIn(guard,job['if'])
        self.assertEqual(job['environment'],'production')
        aws=[x for x in job['steps'] if x.get('uses','').startswith('aws-actions/')][0]
        self.assertEqual(aws['with']['role-to-assume'],'arn:aws:iam::666730517561:role/tims-factory-signing-owner')
        self.assertEqual(aws['with']['disable-retry'],'true')
