import tempfile
from pathlib import Path
import unittest
from unittest.mock import patch

from stage_security_bundle import read_bundle, FILES
from factory_state.scope import canonical
from factory_state.model import StateError
from factory_runtime.worker import digest
import build_bounded_review_package as package


class BundleFileTests(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory();self.addCleanup(temp.cleanup);self.root=Path(temp.name)
        self.bundle=self.root/'bundle';self.bundle.mkdir()
        self.files={name:b'fixture' for name in FILES}
        for name,raw in self.files.items():(self.bundle/name).write_bytes(raw)
        self.raw=canonical({name:digest(raw) for name,raw in self.files.items()})
        self.pins=self.root/'pins.json';self.pins.write_bytes(self.raw)

    def read(self):return read_bundle(self.bundle,self.pins,digest(self.raw),role='security')

    def test_exact_bounded_files_and_independent_manifest(self):
        files,pins=self.read();self.assertEqual(files,self.files)
        self.assertEqual(pins['SECURITY_QA.json'],digest(b'fixture'))

    def test_extra_file_and_modified_manifest_rejected(self):
        (self.bundle/'.env').write_bytes(b'fixture')
        with self.assertRaises(StateError):self.read()
        (self.bundle/'.env').unlink();self.pins.write_bytes(b'{}')
        with self.assertRaises(StateError):self.read()

    def test_symlink_refused_before_read(self):
        original=Path.is_symlink
        with patch.object(Path,'is_symlink',lambda p:p==self.bundle/'SECURITY_QA.json' or original(p)):
            with self.assertRaises(ValueError):self.read()

    def test_cli_routes_separate_material_without_enabling_execution(self):
        with patch.object(package,'build',return_value={'execution_enabled':False}) as build,patch('builtins.print'):
            package.main([str(self.root/'out.zip'),'--role','security','--security-bundle',str(self.bundle),
                '--security-pins',str(self.pins),'--security-pins-digest',digest(self.raw)])
        self.assertEqual(build.call_args.kwargs['security_files'],self.files)
        self.assertNotIn('enabled',build.call_args.kwargs)


if __name__ == '__main__':unittest.main()
