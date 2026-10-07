import unittest

import test_security_entry_cycle as fixtures
from test_security_provider_claims import mock_aws
from stage_security_bundle import stage, FILES
from factory_runtime.worker import digest
from factory_state.model import StateError


@unittest.skipIf(mock_aws is None,'Requires moto[dynamodb] for signed fixture setup')
class BundleTests(unittest.TestCase):
    def setUp(self):
        f=fixtures.EntryCycleTests();f.setUp();self.addCleanup(f.doCleanups);self.f=f
        self.files={name:(f.root/name).read_bytes() for name in FILES}
        self.pins={name:digest(raw) for name,raw in self.files.items()}

    def stage(self):
        return stage(self.files,self.pins,source_commit=self.f.material.binding.qa.source_commit,
            role='security',now=self.f.now)

    def test_validated_bundle_cannot_enable_either_entrypoint(self):
        files,env=self.stage()
        self.assertEqual(files,self.files)
        self.assertEqual(env['FACTORY_SECURITY_ENABLED'],'false')
        self.assertEqual(env['FACTORY_SECURITY_CONTROLLER_ENABLED'],'false')
        self.assertEqual(self.f.signing.calls,0)

    def test_missing_extra_and_unpinned_files_rejected(self):
        original=dict(self.files)
        for change in ('missing','extra','tampered'):
            self.files=dict(original)
            if change=='missing':self.files.pop('SECURITY_QA.json')
            if change=='extra':self.files['.env']=b'not allowed'
            if change=='tampered':self.files['SECURITY_ALLOWANCE.json']=b'{}'
            with self.subTest(change=change),self.assertRaises(StateError):self.stage()

    def test_other_source_and_controller_without_config_rejected(self):
        for source,role in (('f'*40,'security'),(self.f.material.binding.qa.source_commit,'controller')):
            with self.subTest(role=role),self.assertRaises(StateError):
                stage(self.files,self.pins,source_commit=source,role=role,now=self.f.now)


if __name__ == '__main__':unittest.main()
