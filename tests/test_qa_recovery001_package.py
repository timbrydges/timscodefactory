import base64
import copy
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
sys.path[:0]=[str(ROOT/'scripts'),str(ROOT/'src')]
import build_qa_recovery001_package as package
import prepare_qa_recovery001_disabled as deploy
from factory_state.model import StateError


class RecoveryPackageTests(unittest.TestCase):
    def test_reproducible_allowlist_and_disabled_import_from_archive(self):
        def blob(commit,name):return (ROOT/name).read_bytes()
        def git(args,**kw):return '' if args[1]=='status' else 'a'*40+'\n'
        with tempfile.TemporaryDirectory() as directory:
            base=Path(directory);checkout=base/'checkout';checkout.mkdir()
            (checkout/'.env.local').write_text('PRIVATE-TEST-SECRET')
            with patch.object(package,'ROOT',checkout),patch.object(package,'_blob',side_effect=blob),\
                    patch.object(package,'_dependencies',return_value={'fixture-dependency.txt':b'offline fixture'}),\
                    patch.object(package.subprocess,'check_output',side_effect=git):
                first=package.build(base/'first.zip');second=package.build(base/'second.zip')
                self.assertEqual(first,second)
                with self.assertRaises(RuntimeError):package.build(base/'first.zip')
                with self.assertRaises(RuntimeError):package.build(checkout/'forbidden.zip')
            self.assertEqual(first['handler'],package.HANDLER)
            self.assertFalse(first['activation_included']);self.assertFalse(first['execution_enabled'])
            with zipfile.ZipFile(base/'first.zip') as archive:
                names=set(archive.namelist());self.assertNotIn('.env.local',names)
                self.assertNotIn('QA_RECOVERY001_ACTIVATION.json',names)
                index=json.loads(archive.read('PACKAGE.json'))
                for name,sha in index['files'].items():self.assertEqual(hashlib.sha256(archive.read(name)).hexdigest(),sha)
                self.assertTrue(set(package.MODULES)<=names);self.assertTrue(set(package.MATERIAL)<=names)
            # Fresh process imports the actual archive, not modules cached by tests.
            script="import sys,os; sys.path.insert(0,sys.argv[1]); os.environ['FACTORY_QA_RECOVERY001_ENABLED']='false'; from factory_runtime.qa_recovery001_entrypoint import handler; from factory_state.model import StateError\ntry: handler(None,None)\nexcept StateError as e: assert str(e)=='QA recovery entry point disabled'; print('DISABLED')\nelse: raise AssertionError('enabled')"
            result=subprocess.run([sys.executable,'-I','-c',script,str(base/'first.zip')],capture_output=True,text=True,timeout=30)
            self.assertEqual(result.returncode,0,result.stderr);self.assertEqual(result.stdout.strip(),'DISABLED')

    def test_dirty_source_stops_before_install_or_output(self):
        with patch.object(package.subprocess,'check_output',return_value=' M changed.py'),patch.object(package,'_dependencies') as deps:
            with self.assertRaises(RuntimeError):package.build('unused.zip')
            deps.assert_not_called()


class RecoveryDisabledPreviewTests(unittest.TestCase):
    def setUp(self):
        sha=hashlib.sha256(b'fixture package').digest()
        self.package={'source_commit':'a'*40,'sha256':sha.hex(),'code_sha256':base64.b64encode(sha).decode(),
            'zip_bytes':100,'handler':package.HANDLER,'execution_enabled':False,'activation_included':False,
            'signed_allowance_included':False,'model_calls':0}
        self.code={'S3Bucket':deploy.BUCKET,'S3Key':'qa-recovery-001/runtime/'+'a'*40+'/'+sha.hex()+'.zip','S3ObjectVersion':'immutable-version-fixture'}
        self.template=deploy.render(self.package,self.code)
        self.changes={'Status':'CREATE_COMPLETE','ExecutionStatus':'AVAILABLE',
            'StackId':'arn:aws:cloudformation:ca-central-1:666730517561:stack/'+deploy.STACK+'/fixture',
            'Changes':[{'Type':'Resource','ResourceChange':{'LogicalResourceId':name,'ResourceType':r['Type'],'Action':'Add'}} for name,r in self.template['Resources'].items()]}

    def test_only_isolated_disabled_function_and_logs_access(self):
        self.assertEqual(deploy.validate_changes(self.template,self.changes,self.package,self.code)['provider_permissions'],0)
        function=self.template['Resources']['RecoveryFunction']['Properties']
        self.assertEqual(function['ReservedConcurrentExecutions'],0)
        self.assertEqual(function['Environment']['Variables'],{'FACTORY_QA_RECOVERY001_ENABLED':'false'})
        role=self.template['Resources']['RecoveryRole']['Properties'];self.assertNotIn('ManagedPolicyArns',role)
        statements=role['Policies'][0]['PolicyDocument']['Statement']
        self.assertEqual(len(statements),1)
        self.assertEqual(statements[0]['Action'],['logs:CreateLogStream','logs:PutLogEvents'])
        self.assertNotIn('pilot-002',json.dumps(self.template))

    def test_active_packages_mutable_code_and_wrong_handler_rejected(self):
        for change in ({'execution_enabled':True},{'activation_included':True},{'signed_allowance_included':True},
                       {'model_calls':True},{'handler':'other.handler'},{'code_sha256':'wrong'},{'zip_bytes':5000001}):
            with self.subTest(change=change),self.assertRaises(StateError):deploy.render({**self.package,**change},self.code)
        for change in ({'S3ObjectVersion':'null'},{'S3ObjectVersion':''},{'S3Key':'latest.zip'},{'S3Bucket':'other'}):
            with self.subTest(change=change),self.assertRaises(StateError):deploy.render(self.package,{**self.code,**change})

    def test_expanded_permissions_concurrency_or_resource_changes_fail(self):
        for mutate in (lambda t:t['Resources']['RecoveryFunction']['Properties'].update(ReservedConcurrentExecutions=1),
                       lambda t:t['Resources']['RecoveryRole']['Properties']['Policies'][0]['PolicyDocument']['Statement'][0]['Action'].append('bedrock:InvokeModel')):
            template=copy.deepcopy(self.template);mutate(template)
            with self.assertRaises(StateError):deploy.validate_changes(template,self.changes,self.package,self.code)
        for mutate in (lambda c:c.update(NextToken='more'),lambda c:c['Changes'].append(copy.deepcopy(c['Changes'][0])),
                       lambda c:c['Changes'][0]['ResourceChange'].update(Action='Modify')):
            changes=copy.deepcopy(self.changes);mutate(changes)
            with self.assertRaises(StateError):deploy.validate_changes(self.template,changes,self.package,self.code)


if __name__=='__main__':unittest.main()
