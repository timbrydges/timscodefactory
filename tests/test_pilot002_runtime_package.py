import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'scripts'))
import build_pilot002_runtime_package as package
from factory_runtime import pilot002_runtime_probe as p
from factory_state.model import StateError


class RuntimePackageTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.commit='a'*40
        files={name:(ROOT/'src'/name).read_bytes() for name in package.MODULES}
        files.update({name:(ROOT/name).read_bytes() for name in package.MATERIAL})
        files['BUILD.json']=json.dumps({'source_commit':self.commit}).encode()
        for name,raw in files.items():
            path=self.root/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(raw)
        self.index={'source_commit':self.commit,'files':{name:hashlib.sha256(raw).hexdigest() for name,raw in files.items()}}
        self.write_index()
        self.env={p.FLAG:'false',p.ROLE:'builder'}
        self.event={'kind':'pilot002_runtime_probe','source_commit':self.commit,'role':'builder'}

    def write_index(self): (self.root/'PACKAGE.json').write_text(json.dumps(self.index),encoding='utf-8')

    def test_disabled_probe_verifies_crypto_and_all_roles_without_clients(self):
        with patch('boto3.session.Session',side_effect=AssertionError('no AWS clients')), \
             patch('http.client.HTTPSConnection',side_effect=AssertionError('no network')):
            for role in ('builder','inspector','qa'):
                result=p.probe({**self.event,'role':role},root=self.root,env={**self.env,p.ROLE:role})
                self.assertEqual(result['status'],'PILOT002_DISABLED_PACKAGE_VERIFIED')
                self.assertEqual(result['model_calls'],0);self.assertFalse(result['execution_enabled'])

    def test_missing_or_enabled_flag_rejects_before_package_read(self):
        for value in (None,'true','False','0'):
            with self.subTest(value=value),self.assertRaises(StateError):
                p.probe(self.event,root=self.root/'missing',env={**self.env,p.FLAG:value})

    def test_wrong_event_role_source_and_extra_fields_rejected(self):
        for change in ({'kind':'run_once'},{'source_commit':'b'*40},{'role':'qa'},{'allowance':{}}):
            with self.subTest(change=change),self.assertRaises(StateError):p.probe({**self.event,**change},root=self.root,env=self.env)

    def test_changed_missing_or_oversized_content_rejected(self):
        path=self.root/'BUILD.json';original=path.read_bytes()
        for value in (b'{}',b'x'*16777217):
            path.write_bytes(value)
            with self.assertRaises(StateError):p.probe(self.event,root=self.root,env=self.env)
        path.write_bytes(original);path.unlink()
        with self.assertRaises(StateError):p.probe(self.event,root=self.root,env=self.env)

    def test_unsafe_manifest_paths_rejected(self):
        for name in ('../outside','/absolute','C:/secret','factory_runtime\\x.py','a//b'):
            self.index['files'][name]='0'*64;self.write_index()
            with self.subTest(name=name),self.assertRaises(StateError):p.probe(self.event,root=self.root,env=self.env)
            del self.index['files'][name]

    def test_reproducible_allowlisted_archive_no_untracked_or_old_handlers(self):
        outputs=[self.root/'one.zip',self.root/'two.zip']
        def blob(commit,name):return (ROOT/name).read_bytes()
        for output in outputs:
            with patch.object(package.subprocess,'check_output',side_effect=['',self.commit]), \
                 patch.object(package,'_blob',side_effect=blob), \
                 patch.object(package,'_dependencies',return_value={'dependency/fixture.py':b'# synthetic'}):
                package.build(output)
        self.assertEqual(outputs[0].read_bytes(),outputs[1].read_bytes())
        with zipfile.ZipFile(outputs[0]) as archive:
            names=archive.namelist()
            self.assertNotIn('.env.local',names);self.assertNotIn('factory_runtime/lambda_role.py',names)
            self.assertNotIn('factory/profiles/scope-signers.json',names)
            self.assertTrue(all(item.create_system==3 for item in archive.infolist()))
            index=json.loads(archive.read('PACKAGE.json'))
            self.assertEqual(set(names),set(index['files'])|{'PACKAGE.json'})
            for name,digest in index['files'].items():self.assertEqual(hashlib.sha256(archive.read(name)).hexdigest(),digest)

    def test_dirty_checkout_and_output_overwrite_rejected(self):
        with patch.object(package.subprocess,'check_output',return_value=' M file'),self.assertRaises(RuntimeError):
            package.build(self.root/'new.zip')
        output=self.root/'exists.zip';output.write_bytes(b'keep')
        with patch.object(package.subprocess,'check_output',side_effect=['',self.commit]),self.assertRaises(RuntimeError):package.build(output)
        self.assertEqual(output.read_bytes(),b'keep')

    @unittest.skipUnless(sys.platform=='linux' and sys.version_info[:2]==(3,12),'Linux Python 3.12 package smoke test')
    def test_real_linux_wheels_and_isolated_package_probe(self):
        archive=self.root/'linux.zip';result=package.build(archive)
        repeated=package.build(self.root/'linux-repeat.zip')
        self.assertEqual(result['sha256'],repeated['sha256'])
        extracted=self.root/'extracted'
        with zipfile.ZipFile(archive) as z:z.extractall(extracted)
        code=('import json,sys;from pathlib import Path;sys.path.insert(0,sys.argv[1]);'
            'from factory_runtime.pilot002_runtime_probe import probe;'
            'root=Path(sys.argv[1]);commit=json.loads((root/"BUILD.json").read_bytes())["source_commit"];'
            'print(json.dumps(probe({"kind":"pilot002_runtime_probe","source_commit":commit,"role":"builder"},'
            'root=root,env={"FACTORY_PILOT002_EXECUTION_ENABLED":"false","FACTORY_PILOT002_ROLE":"builder"})))')
        completed=subprocess.run([sys.executable,'-I','-c',code,str(extracted)],cwd=self.root,
            capture_output=True,text=True,timeout=45,check=True)
        value=json.loads(completed.stdout)
        self.assertEqual(value['source_commit'],result['source_commit'])
        self.assertEqual(value['cryptography_version'],'46.0.5');self.assertEqual(value['model_calls'],0)


if __name__=='__main__':unittest.main()
