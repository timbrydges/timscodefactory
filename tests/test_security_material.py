"""Authenticated importer fixtures only; no live authority or provider IO."""
from dataclasses import replace
from datetime import timedelta
import json
import unittest

import test_review_material as fixtures
from factory_runtime.security_material import PinnedSecurityMaterial
from factory_runtime.worker import digest
from factory_state.model import StateError


class SecurityMaterialTests(unittest.TestCase):
    def setUp(self):
        self.f = fixtures.MaterialTests(); self.f.setUp(); self.addCleanup(self.f.doCleanups)
        self.qa = self.f.load().binding('qa')

    def load(self, **changes):
        args = dict(raw=self.f.raw, expected_digest=digest(self.f.raw),
            deployed_commit=self.f.f.commit, qa_binding=self.qa,
            qa_result_digest=digest(b'fixture signed QA result'), clock=lambda:self.f.f.now)
        args.update(changes)
        return PinnedSecurityMaterial.load(**args)

    def test_new_contract_binds_complete_request_and_fresh_proof(self):
        material = self.load(); prepared = material.prepared(); prepared.validate()
        self.assertNotEqual(prepared.scope.request.contract_digest, self.qa.contract_digest)
        self.assertEqual(prepared.scope.request.input_digest, digest(prepared.input_bytes))
        value = json.loads(material.contract_bytes)
        self.assertEqual(value['prior_qa_binding']['contract_digest'], self.qa.contract_digest)
        self.assertFalse(value['historical_authority_renewed'])
        self.assertEqual(material.evidence(clock=lambda:self.f.f.now).binding, material.binding.qa)

    def test_unpinned_or_expired_import_is_rejected(self):
        for change in ({'expected_digest':digest(b'other')}, {'deployed_commit':'f'*40},
                       {'clock':lambda:self.f.f.now+timedelta(hours=2)}):
            with self.subTest(change=change), self.assertRaises(StateError):self.load(**change)

    def test_historical_candidate_and_role_substitution_rejected(self):
        for change in ({'candidate_commit':'c'*40}, {'candidate_digest':digest(b'other')},
                       {'role_id':'independent_inspector'}, {'task_id':'other'}):
            with self.subTest(change=change), self.assertRaises(StateError):
                self.load(qa_binding=replace(self.qa, **change))

    def test_distinct_qa_receipt_changes_contract_input_and_request(self):
        first = self.load(); second = self.load(qa_result_digest=digest(b'another receipt'))
        self.assertNotEqual(first.contract_bytes, second.contract_bytes)
        self.assertNotEqual(first.prepared().scope.request_bytes, second.prepared().scope.request_bytes)
        self.assertEqual(first.candidate_bytes, second.candidate_bytes)


if __name__ == '__main__': unittest.main()
