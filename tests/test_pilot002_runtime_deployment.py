import copy
import sys
import unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'scripts'))
import prepare_pilot002_runtime as p
from factory_state.model import StateError


class RuntimeDeploymentTests(unittest.TestCase):
    def setUp(self):
        self.args={'source_commit':'a'*40,'code':{'S3Bucket':'fixture','S3Key':'runtime.zip','S3ObjectVersion':'immutable-version'}}
        self.template=p.render(**self.args)
        self.change_set={'Status':'CREATE_COMPLETE','ExecutionStatus':'AVAILABLE',
            'StackId':f'arn:aws:cloudformation:{p.REGION}:{p.ACCOUNT}:stack/{p.STACK}/fixture',
            'Changes':[{'Type':'Resource','ResourceChange':{'LogicalResourceId':name,'Action':'Add','ResourceType':value['Type']}}
                for name,value in self.template['Resources'].items()]}

    def test_only_new_disabled_functions_and_own_logs(self):
        self.assertEqual(len(self.template['Resources']),9)
        for role in p.ROLES:
            fn=self.template['Resources'][role.title()+'Function']['Properties']
            self.assertEqual(fn['ReservedConcurrentExecutions'],0)
            self.assertEqual(fn['Environment']['Variables']['FACTORY_PILOT002_EXECUTION_ENABLED'],'false')
            iam=self.template['Resources'][role.title()+'Role']['Properties']
            self.assertNotIn('ManagedPolicyArns',iam)
            statements=iam['Policies'][0]['PolicyDocument']['Statement']
            self.assertEqual(len(statements),1)
            self.assertEqual(statements[0]['Action'],['logs:CreateLogStream','logs:PutLogEvents'])
            self.assertTrue(statements[0]['Resource'].endswith('/aws/lambda/'+fn['FunctionName']+':*'))
        self.assertEqual(p.validate_changes(self.template,self.change_set,**self.args)['status'],'VALIDATED_NOT_EXECUTED')

    def test_mutable_code_source_and_template_mutations_rejected(self):
        for code in ({'S3Bucket':'b','S3Key':'k'},{**self.args['code'],'S3ObjectVersion':'null'}):
            with self.assertRaises(StateError):p.render(source_commit='a'*40,code=code)
        for target,key,value in (('BuilderFunction','ReservedConcurrentExecutions',1),
            ('BuilderFunction','Handler','active.handler'),('BuilderRole','ManagedPolicyArns',['admin'])):
            changed=copy.deepcopy(self.template);changed['Resources'][target]['Properties'][key]=value
            with self.assertRaises(StateError):p.validate_changes(changed,self.change_set,**self.args)

    def test_resource_removal_duplicates_modifications_and_wrong_account_rejected(self):
        variants=[]
        changed=copy.deepcopy(self.change_set);changed['Changes'].pop();variants.append(changed)
        changed=copy.deepcopy(self.change_set);changed['Changes'][1]=changed['Changes'][0];variants.append(changed)
        changed=copy.deepcopy(self.change_set);changed['Changes'][0]['ResourceChange']['Action']='Modify';variants.append(changed)
        variants.extend({**self.change_set,**change} for change in ({'NextToken':'more'},
            {'ExecutionStatus':'EXECUTE_COMPLETE'},{'Status':'FAILED'},{'StackId':'wrong-account'},
            {'Parameters':[{'ParameterKey':'override','ParameterValue':'true'}]}))
        for changed in variants:
            with self.subTest(changed=changed),self.assertRaises(StateError):p.validate_changes(self.template,changed,**self.args)

    def test_input_code_is_copied(self):
        self.args['code']['S3Key']='changed'
        self.assertEqual(self.template['Resources']['BuilderFunction']['Properties']['Code']['S3Key'],'runtime.zip')


if __name__=='__main__':unittest.main()
