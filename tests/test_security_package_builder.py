"""Builder integration; bundle validation is independently covered with signatures."""
import hashlib
import json
import unittest
from unittest.mock import patch
import zipfile

import build_bounded_review_package as package
import test_bounded_review_package as fixtures


class SecurityPackageTests(unittest.TestCase):
    def setUp(self):
        f=fixtures.BoundedPackageTests();f.setUp();self.addCleanup(f.doCleanups);self.f=f

    def test_validated_bundle_is_indexed_and_execution_flags_remain_disabled(self):
        files={'SECURITY_QA.json':b'fixture-public-material'};pins={'SECURITY_QA.json':'fixture-pin'}
        env={'FACTORY_SECURITY_ENABLED':'false','FACTORY_SECURITY_CONTROLLER_ENABLED':'false'}
        output=self.f.base/'security.zip'
        with patch.object(package,'ROOT',self.f.root),patch.object(package,'_dependencies',return_value={}), \
                patch.object(package,'stage_security_bundle',return_value=(files,env)) as stage:
            result=package.build(output,role='security',security_files=files,security_pins=pins)
        self.assertEqual(stage.call_args.args,(files,pins))
        self.assertEqual(stage.call_args.kwargs['source_commit'],result['source_commit'])
        self.assertFalse(result['execution_enabled']);self.assertFalse(result['deployment_authority_verified'])
        self.assertEqual(result['environment'],env)
        with zipfile.ZipFile(output) as archive:
            index=json.loads(archive.read('PACKAGE.json'))
            self.assertEqual(archive.read('SECURITY_QA.json'),files['SECURITY_QA.json'])
            self.assertEqual(index['files']['SECURITY_QA.json'],hashlib.sha256(files['SECURITY_QA.json']).hexdigest())
            self.assertNotIn('.env.local',archive.namelist())

    def test_partial_or_cross_role_material_rejected_before_dependencies(self):
        cases=({'role':'security'},{'role':'security','security_files':{},'security_pins':{},'material':'old'},
               {'role':'qa','security_files':{},'security_pins':{}})
        with patch.object(package,'ROOT',self.f.root),patch.object(package,'_dependencies') as deps:
            for args in cases:
                with self.subTest(args=args),self.assertRaises(ValueError):package.build(self.f.base/'bad.zip',**args)
            deps.assert_not_called()

    def test_bundle_validation_failure_creates_no_output(self):
        output=self.f.base/'bad.zip'
        with patch.object(package,'ROOT',self.f.root),patch.object(package,'_dependencies') as deps, \
                patch.object(package,'stage_security_bundle',side_effect=ValueError('fixture invalid')):
            with self.assertRaises(ValueError):package.build(output,role='security',security_files={},security_pins={})
            deps.assert_not_called();self.assertFalse(output.exists())


if __name__ == '__main__':unittest.main()
