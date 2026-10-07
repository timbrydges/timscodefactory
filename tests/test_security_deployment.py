import json
import tempfile
import unittest
from dataclasses import asdict
from pathlib import Path

import test_security_material as fixtures
from factory_runtime.security_deployment import load_deployment
from factory_runtime.worker import digest
from factory_state.model import StateError
from factory_state.scope import canonical


class SecurityDeploymentTests(unittest.TestCase):
    def setUp(self):
        f=fixtures.SecurityMaterialTests();f.setUp();self.addCleanup(f.doCleanups);self.f=f
        temp=tempfile.TemporaryDirectory();self.addCleanup(temp.cleanup);self.root=Path(temp.name)
        (self.root/'BUILD.json').write_bytes(canonical({'source_commit':f.f.f.commit}))
        (self.root/'REVIEW_MATERIAL.json').write_bytes(f.f.raw)
        self.doc={'kind':'bounded_security004_qa_provenance','qa_binding':asdict(f.qa),
            'qa_request':asdict(f.f.load().prepared('qa').scope.request),
            'qa_result_digest':digest(b'fixture QA result')}
        self.env={'FACTORY_SECURITY_MATERIAL_DIGEST':digest(f.f.raw)}
        self.save()

    def save(self):
        raw=canonical(self.doc);(self.root/'SECURITY_QA.json').write_bytes(raw)
        self.env['FACTORY_SECURITY_QA_DIGEST']=digest(raw)

    def load(self):return load_deployment(self.root,self.env,clock=lambda:self.f.f.f.now)

    def test_exact_files_produce_separate_security_contract(self):
        deployment=self.load()
        self.assertEqual(deployment.qa_binding,self.f.qa)
        self.assertNotEqual(deployment.material.binding.qa.contract_digest,self.f.qa.contract_digest)
        deployment.material.prepared().validate()

    def test_unpinned_qa_bytes_rejected(self):
        (self.root/'SECURITY_QA.json').write_bytes(b'{}')
        with self.assertRaises(StateError):self.load()

    def test_recomputed_pin_does_not_accept_wrong_dispatch_or_extra_fields(self):
        original=json.loads(canonical(self.doc))
        for change in ('dispatch','extra','role'):
            self.doc=json.loads(canonical(original))
            if change=='dispatch':self.doc['qa_request']['input_digest']=digest(b'other')
            if change=='extra':self.doc['enabled']=True
            if change=='role':self.doc['qa_binding']['role_id']='independent_inspector'
            self.save()
            with self.subTest(change=change),self.assertRaises(StateError):self.load()


if __name__ == '__main__':unittest.main()
