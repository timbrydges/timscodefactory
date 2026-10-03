import copy
from pathlib import Path
import sys
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
import prepare_pilot002_builder_stage as p


class BuilderStageTests(unittest.TestCase):
    def setUp(self):
        self.current=p.access_template(p.baseline())
        self.package={'source_commit':p.SOURCE,'execution_enabled':False,'model_calls':0,
            'handler':'factory_runtime.pilot002_runtime_probe.handler','sha256':'a'*64}
        self.code={'S3Bucket':p.BUCKET,'S3Key':'pilot-002/runtime/'+p.SOURCE+'/'+'a'*64+'.zip','S3ObjectVersion':'immutable-version'}
        self.changes={'Status':'CREATE_COMPLETE','ExecutionStatus':'AVAILABLE',
            'StackId':f'arn:aws:cloudformation:{p.REGION}:{p.ACCOUNT}:stack/{p.STACK}/fixture',
            'Changes':[{'Type':'Resource','ResourceChange':{'LogicalResourceId':'BuilderFunction',
                'ResourceType':'AWS::Lambda::Function','Action':'Modify','Replacement':'False'}}]}

    def test_only_builder_changes_while_disabled_and_policies_unchanged(self):
        result=p.render(self.current,self.package,self.code)
        for name,value in self.current['Resources'].items():
            if name!='BuilderFunction':self.assertEqual(result['Resources'][name],value)
        props=result['Resources']['BuilderFunction']['Properties']
        self.assertEqual(props['ReservedConcurrentExecutions'],0)
        self.assertEqual(props['Environment']['Variables']['FACTORY_PILOT002_EXECUTION_ENABLED'],'false')
        self.assertNotIn('FACTORY_PILOT002_ACTIVATION_SHA256',props['Environment']['Variables'])
        self.assertEqual(props['Timeout'],180)
        self.assertEqual(p.validate(result,self.changes,self.package,self.code)['status'],'BUILDER_STAGE_VALIDATED_NOT_EXECUTED')

    def test_drifted_baseline_package_or_mutable_artifact_rejected(self):
        changed=copy.deepcopy(self.current);changed['Resources']['BuilderFunction']['Properties']['ReservedConcurrentExecutions']=1
        with self.assertRaises(p.StateError):p.render(changed,self.package,self.code)
        for patch in ({'execution_enabled':True},{'source_commit':'b'*40},{'activation_sha256':'c'*64}):
            with self.assertRaises(p.StateError):p.render(self.current,{**self.package,**patch},self.code)
        for patch in ({'S3ObjectVersion':'null'},{'S3Bucket':'other'},{'S3Key':'other'}):
            with self.assertRaises(p.StateError):p.render(self.current,self.package,{**self.code,**patch})

    def test_replacement_extra_resource_or_changed_template_rejected(self):
        template=p.render(self.current,self.package,self.code)
        for patch in ({'Replacement':'True'},{'LogicalResourceId':'QaFunction'},{'Action':'Add'}):
            changes=copy.deepcopy(self.changes);changes['Changes'][0]['ResourceChange'].update(patch)
            with self.assertRaises(p.StateError):p.validate(template,changes,self.package,self.code)
        changes=copy.deepcopy(self.changes);changes['Changes']*=2
        with self.assertRaises(p.StateError):p.validate(template,changes,self.package,self.code)
        template['Resources']['BuilderFunction']['Properties']['ReservedConcurrentExecutions']=1
        with self.assertRaises(p.StateError):p.validate(template,self.changes,self.package,self.code)


if __name__=='__main__':unittest.main()
