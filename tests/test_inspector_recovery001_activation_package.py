import copy
import hashlib
import json
import sys
import tempfile
import unittest
import zipfile
from datetime import timedelta
from pathlib import Path
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'scripts'),str(ROOT/'src')]
import build_inspector_recovery001_activation_package as p
import prepare_inspector_recovery001_disabled as disabled
import test_inspector_recovery001_runtime as runtime
from factory_state.scope import canonical


class RecoveryActivationPackageTests(unittest.TestCase):
    def setUp(self):
        self.fixture=runtime.RecoveryRuntimeTests();self.fixture.setUp()
        self.doc=copy.deepcopy(self.fixture.doc);self.now=self.fixture.now
        self.files={name:(ROOT/name).read_bytes() for name in p.inert.MATERIAL}
        self.files['BUILD.json']=canonical({'source_commit':self.doc['source_commit']})

    def test_exact_public_material_validates_without_authority(self):
        result=p.validate_material(self.files,canonical(self.doc),self.now)
        self.assertEqual(result['request_digest'],p.REQUEST_DIGEST)
        self.assertEqual(result['maximum_cost_micro_usd'],159744)
        self.assertFalse(result['activation_authorized'])
        self.assertLessEqual(result['material_expires_at'],self.doc['readiness']['expires_at'])

    def test_stale_or_substituted_material_is_rejected(self):
        for update in ({'kind':'pilot002_activation'},{'candidate_commit':'0'*40},
                       {'source_commit':'0'*40},{'builder_response_base64':'e30='},
                       {'capture_failed_review_response':False},{'credential':{'kind':'secret'}},
                       {'allowance':{'signature':'unexpected'}}):
            with self.subTest(update=update),self.assertRaises(Exception):
                p.validate_material(self.files,canonical({**self.doc,**update}),self.now)
        for when in (self.now+timedelta(hours=2),self.now.replace(tzinfo=None)):
            with self.assertRaises(Exception):p.validate_material(self.files,canonical(self.doc),when)
        for raw in (b'',b'x'*131073,canonical(self.doc)[:-1]+b',"kind":"duplicate"}'):
            with self.assertRaises(Exception):p.validate_material(self.files,raw,self.now)
        bad=copy.deepcopy(self.doc);bad['readiness']['request_digest']='sha256:'+'0'*64
        with self.assertRaises(Exception):p.validate_material(self.files,canonical(bad),self.now)
        bad=copy.deepcopy(self.doc);bad['qualification']['input_micro_usd_per_million']=1000000000
        with self.assertRaises(Exception):p.validate_material(self.files,canonical(bad),self.now)
        bad=copy.deepcopy(self.doc);bad['signer_registry']['signers'][0]['revoked']=True
        with self.assertRaises(Exception):p.validate_material(self.files,canonical(bad),self.now)
        bad_files=dict(self.files);bad_files['factory/autonomy/inspector-recovery-001-scope.json']=b'{}'
        with self.assertRaises(Exception):p.validate_material(bad_files,canonical(self.doc),self.now)

    def test_packaging_is_reproducible_and_does_not_enable_disabled_deployer(self):
        source=self.doc['source_commit']
        def blob(commit,name):
            return self.files[name] if name in self.files else (ROOT/name).read_bytes()
        def git(args,**kw):return '' if args[1]=='status' else source+'\n'
        with tempfile.TemporaryDirectory() as directory:
            base=Path(directory);activation=base/'public.json';activation.write_bytes(canonical(self.doc))
            with patch.object(p.inert,'_blob',side_effect=blob),\
                    patch.object(p.inert,'_dependencies',return_value={'offline.txt':b'fixture'}),\
                    patch.object(p.inert.subprocess,'check_output',side_effect=git):
                first=p.build(base/'first.zip',activation=activation,now=self.now)
                second=p.build(base/'second.zip',activation=activation,now=self.now)
                self.assertEqual(first,second)
                with self.assertRaises(RuntimeError):p.build(base/'first.zip',activation=activation,now=self.now)
            self.assertTrue(first['activation_included']);self.assertFalse(first['execution_enabled'])
            self.assertFalse(first['signed_allowance_included']);self.assertEqual(first['model_calls'],0)
            with zipfile.ZipFile(base/'first.zip') as archive:
                index=json.loads(archive.read('PACKAGE.json'))
                self.assertEqual(set(archive.namelist()),set(index['files'])|{'PACKAGE.json'})
                for name,sha in index['files'].items():self.assertEqual(hashlib.sha256(archive.read(name)).hexdigest(),sha)
                self.assertEqual(archive.read(p.ACTIVATION),activation.read_bytes())
            with self.assertRaises(Exception):disabled.render(first,{})

    def test_invalid_material_leaves_no_output(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);activation=root/'bad.json';activation.write_bytes(b'x'*131073)
            with patch.object(p.inert,'build') as inert_build:
                with self.assertRaises(ValueError):p.build(root/'output.zip',activation=activation)
                inert_build.assert_not_called()
            self.assertFalse((root/'output.zip').exists())


if __name__=='__main__':unittest.main()
