"""Mocked GitHub transport only: these fixtures never authorize runtime work."""
import json
from datetime import timedelta
import unittest

import test_review_test_proof_import as fixtures
from scripts.prepare_bounded_review_material import prepare
from factory_runtime.review_material import PinnedReviewMaterial, CANDIDATE, CANDIDATE_DIGEST
from factory_runtime.review_provider_scope import PROVIDERS
from factory_runtime.worker import digest
from factory_state.model import StateError
from factory_state.scope import canonical


class MaterialTests(unittest.TestCase):
    def setUp(self):
        self.f=fixtures.TestProofImportTests();self.f.setUp();self.addCleanup(self.f.doCleanups)
        self.raw=prepare(self.f.commit,123,api=self.f.api,clock=lambda:self.f.now)

    def load(self,raw=None,commit=None,now=None):
        raw=self.raw if raw is None else raw
        return PinnedReviewMaterial.load(raw,expected_digest=digest(raw),
            deployed_commit=commit or self.f.commit,clock=lambda:now or self.f.now)

    def test_authenticated_import_derives_three_routes_one_candidate_and_fixed_contract(self):
        self.assertEqual(self.f.api.call_count,4)
        material=self.load();requests=[material.prepared(r) for r in PROVIDERS]
        self.assertEqual(len({r.scope.request.lease_id for r in requests}),3)
        self.assertEqual(len({r.scope.request.input_digest for r in requests}),3)
        self.assertEqual({r.scope.candidate_commit for r in requests},{CANDIDATE})
        self.assertEqual({r.scope.candidate_digest for r in requests},{CANDIDATE_DIGEST})
        for role in ('inspector','qa'):
            self.assertTrue(material.evidence(role,clock=lambda:self.f.now)(
                CANDIDATE,CANDIDATE_DIGEST,digest(material.proof_bytes)))
        contract=json.loads(material.contract_bytes)
        self.assertEqual(contract['run_reserved_micro_usd'],500000)
        self.assertFalse(contract['production_release_authorized'])
        files=material.files();files['fingerprint.py']='changed'
        self.assertNotEqual(files,material.files())

    def test_unpinned_bytes_wrong_source_and_expired_proof_rejected(self):
        with self.assertRaises(StateError):
            PinnedReviewMaterial.load(self.raw+b' ',expected_digest=digest(self.raw),
                deployed_commit=self.f.commit,clock=lambda:self.f.now)
        with self.assertRaises(StateError):self.load(commit='a'*40)
        with self.assertRaises(StateError):self.load(now=self.f.now+timedelta(hours=2))

    def test_recomputed_hash_cannot_swap_candidate_or_invent_authority(self):
        for change in ({'candidate_commit':'a'*40},{'gate_authority':True},
                       {'model_calls':False},{'run_id':True},{'workflow':'other.yml'},
                       {'proof_base64':'e30='}):
            value=json.loads(self.raw);value['test_proof'].update(change)
            with self.subTest(change=change),self.assertRaises(StateError):self.load(canonical(value))
        value=json.loads(self.raw);value['candidate_files']['fingerprint.py']='print(1)'
        with self.assertRaises(StateError):self.load(canonical(value))

    def test_changed_main_is_rejected_by_preparer(self):
        self.f.responses['repos/'+fixtures.REPOSITORY+'/git/ref/heads/main']=canonical({'object':{'sha':'a'*40}})
        with self.assertRaises(StateError):
            prepare(self.f.commit,123,api=self.f.api,clock=lambda:self.f.now)

    def test_noncanonical_material_and_unconfigured_roles_rejected(self):
        with self.assertRaises(StateError):self.load(self.raw+b'\n')
        with self.assertRaises(StateError):self.load().prepared('planner')
        with self.assertRaises(StateError):self.load().binding('builder')
