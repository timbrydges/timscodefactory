import base64
import copy
import sys
from pathlib import Path
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
import prepare_pilot002_reviewer_stage as p


class ReviewerStageTests(unittest.TestCase):
    def setUp(self):
        self.package={'source_commit':p.SOURCE,'execution_enabled':False,'model_calls':0,
            'handler':'factory_runtime.pilot002_runtime_probe.handler','sha256':'a'*64,
            'code_sha256':base64.b64encode(bytes.fromhex('a'*64)).decode()}
        self.code={'S3Bucket':p.BUCKET,'S3Key':'pilot-002/runtime/'+p.SOURCE+'/'+'a'*64+'.zip',
            'S3ObjectVersion':'immutable-version'}
        self.changes={'Status':'CREATE_COMPLETE','ExecutionStatus':'AVAILABLE',
            'StackId':f'arn:aws:cloudformation:{p.REGION}:{p.ACCOUNT}:stack/{p.STACK}/fixture',
            'Changes':[{'Type':'Resource','ResourceChange':{'LogicalResourceId':name,
                'ResourceType':'AWS::Lambda::Function','Action':'Modify','Replacement':'False'}} for name in p.REVIEWERS]}

    def test_only_reviewers_change_without_activation_or_access_changes(self):
        before=p.baseline();after=p.render(before,self.package,self.code)
        for name,value in before['Resources'].items():
            if name not in p.REVIEWERS:self.assertEqual(after['Resources'][name],value)
            else:
                props=after['Resources'][name]['Properties']
                self.assertEqual(props['Environment'],value['Properties']['Environment'])
                self.assertEqual(props['ReservedConcurrentExecutions'],0)
                self.assertEqual(props['Timeout'],180)
        self.assertEqual(p.validate(after,self.changes,self.package,self.code)['provider_calls'],0)

    def test_drift_activation_wrong_hash_and_mutable_version_rejected(self):
        before=p.baseline();changed=copy.deepcopy(before)
        changed['Resources']['BuilderFunction']['Properties']['ReservedConcurrentExecutions']=1
        with self.assertRaises(p.StateError):p.render(changed,self.package,self.code)
        for patch in ({'activation_sha256':'b'*64},{'execution_enabled':True},{'source_commit':'b'*40},
                      {'code_sha256':'wrong'},{'model_calls':False}):
            with self.assertRaises(p.StateError):p.render(before,{**self.package,**patch},self.code)
        for patch in ({'S3ObjectVersion':'null'},{'S3Bucket':'other'},{'S3Key':'other'}):
            with self.assertRaises(p.StateError):p.render(before,self.package,{**self.code,**patch})

    def test_extra_duplicate_replacement_and_activation_changes_rejected(self):
        template=p.render(p.baseline(),self.package,self.code)
        for field,value in [('Replacement','True'),('LogicalResourceId','BuilderFunction'),('Action','Add')]:
            changes=copy.deepcopy(self.changes);changes['Changes'][0]['ResourceChange'][field]=value
            with self.assertRaises(p.StateError):p.validate(template,changes,self.package,self.code)
        for items in ([self.changes['Changes'][0]]*2,self.changes['Changes']*2):
            with self.assertRaises(p.StateError):p.validate(template,{**self.changes,'Changes':items},self.package,self.code)
        template['Resources']['InspectorFunction']['Properties']['Environment']['Variables']['FACTORY_PILOT002_EXECUTION_ENABLED']='true'
        with self.assertRaises(p.StateError):p.validate(template,self.changes,self.package,self.code)
