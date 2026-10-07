"""Controller parsing fixtures; allowance authentication tested separately."""
from dataclasses import replace
from datetime import timedelta
import json
import unittest

import test_security_deployment as fixtures
from factory_runtime.security_controller_config import load_controller_config
from factory_runtime.security_provider_scope import VerifiedSecurityAllowance
from factory_runtime.worker import digest
from factory_state.model import StateError
from factory_state.scope import canonical


class ControllerConfigTests(unittest.TestCase):
    def setUp(self):
        f=fixtures.SecurityDeploymentTests();f.setUp();self.addCleanup(f.doCleanups);self.f=f
        self.deployment=f.load();self.now=f.f.f.f.now;q=self.deployment.material.binding.qa
        scope=self.deployment.material.prepared().scope
        self.grant=VerifiedSecurityAllowance(digest(b'fixture'),digest(canonical(scope.bindings())),
            159744,int(self.now.timestamp())+600)
        self.doc={'activation':{'activation_id':'bounded-security-004','factory_id':q.factory_id,
            'task_id':q.task_id,'source_commit':q.source_commit,'contract_digest':q.contract_digest,
            'starts_at':self.now.isoformat(),'expires_at':(self.now+timedelta(minutes=5)).isoformat()},
            'function_arn':'arn:aws:lambda:ca-central-1:666730517561:function:tims-factory-review-security:1',
            'job_versions':{'SECURITY_REVIEW':{'version_id':'fixture-v1','sha256':digest(b'job')}}}

    def load(self):
        raw=canonical(self.doc);(self.f.root/'SECURITY_CONTROLLER.json').write_bytes(raw)
        self.f.env['FACTORY_SECURITY_CONTROLLER_DIGEST']=digest(raw)
        return load_controller_config(self.f.root,self.f.env,deployment=self.deployment,grant=self.grant,now=self.now)

    def test_exact_bounded_security_stage_loads(self):
        config=self.load()
        self.assertEqual(config.job_version.version_id,'fixture-v1')
        self.assertEqual(config.activation.contract_digest,self.deployment.material.binding.qa.contract_digest)

    def test_alias_extra_stage_and_unversioned_job_rejected(self):
        original=json.loads(canonical(self.doc))
        for change in ('alias','stage','version'):
            self.doc=json.loads(canonical(original))
            if change=='alias':self.doc['function_arn']=self.doc['function_arn'][:-1]+'live'
            if change=='stage':self.doc['job_versions']['RELEASE_READY']=self.doc['job_versions']['SECURITY_REVIEW']
            if change=='version':self.doc['job_versions']['SECURITY_REVIEW']['version_id']='null'
            with self.subTest(change=change),self.assertRaises(StateError):self.load()

    def test_changed_source_and_allowance_window_rejected(self):
        original=json.loads(canonical(self.doc))
        self.doc['activation']['source_commit']='f'*40
        with self.assertRaises(StateError):self.load()
        self.doc=original
        self.grant=replace(self.grant,expires_at=int(self.now.timestamp())+60)
        with self.assertRaises(StateError):self.load()

    def test_unrelated_verified_allowance_cannot_configure_controller(self):
        self.grant=replace(self.grant,scope_digest=digest(b'other scope'))
        with self.assertRaises(StateError):self.load()


if __name__ == '__main__':unittest.main()
