import base64
import copy
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT/'src'), str(ROOT/'scripts')]
from factory_state.model import StateError
from prepare_review_role_bootstrap import render
from prepare_security_validation_deployment import prepare, validate_changes, STACK_PREFIX


class DeploymentTests(unittest.TestCase):
    def setUp(self):
        self.current = render()
        self.package = {'source_commit':'a'*40,'sha256':'b'*64,
            'code_sha256':base64.b64encode(bytes.fromhex('b'*64)).decode(),'zip_bytes':6358021}
        self.plan = prepare(self.current,self.package,object_version='immutable-s3-version')
        self.stack = STACK_PREFIX+'12345678'
        self.change_set = {'StackId':self.stack,'Status':'CREATE_COMPLETE','ExecutionStatus':'AVAILABLE',
            'Parameters':[{'ParameterKey':k,'ParameterValue':'original-'+k} for k in self.current['Parameters']],
            'Changes':[
                {'Type':'Resource','ResourceChange':{'LogicalResourceId':'SecurityFunction','Action':'Modify',
                    'ResourceType':'AWS::Lambda::Function','Replacement':'False','Scope':['Properties'],
                    'Details':[{'Target':{'Attribute':'Properties','Name':k,'RequiresRecreation':'Never'}}
                               for k in ('Code','Handler','Timeout')]}},
                {'Type':'Resource','ResourceChange':{'LogicalResourceId':self.plan['version_logical_id'],
                    'Action':'Add','ResourceType':'AWS::Lambda::Version'}}]}

    def validate(self, changes=None, proposed=None, plan=None):
        return validate_changes(plan or self.plan, self.current,
            self.plan['template'] if proposed is None else proposed,
            self.change_set if changes is None else changes, stack_id=self.stack,current_parameters={k:'original-'+k for k in self.current['Parameters']})

    def test_additive_template_preserves_every_other_resource_and_parameter(self):
        before = copy.deepcopy(self.current)
        self.assertEqual(self.validate()['status'],'SECURITY_CHANGE_SET_VALIDATED_NOT_EXECUTED')
        self.assertEqual(self.current,before)
        for name, resource in self.current['Resources'].items():
            if name != 'SecurityFunction': self.assertEqual(self.plan['template']['Resources'][name],resource)
        self.assertEqual(self.plan['template']['Parameters'],self.current['Parameters'])
        self.assertFalse(self.plan['execution_authorized'])
        self.assertFalse(self.plan['gate_authority'])

    def test_next_version_keeps_both_original_and_previously_added_versions(self):
        current = self.plan['template']
        package = {**self.package,'sha256':'c'*64,
                   'code_sha256':base64.b64encode(bytes.fromhex('c'*64)).decode()}
        next_plan = prepare(current,package,object_version='second-version')
        for name in ('SecurityVersion',self.plan['version_logical_id'],'QaVersion'):
            self.assertEqual(next_plan['template']['Resources'][name],current['Resources'][name])
        with self.assertRaises(StateError): prepare(current,self.package,object_version='immutable-s3-version')

    def test_existing_manual_version_name_cannot_republish_the_same_package(self):
        current=copy.deepcopy(self.current)
        current['Resources']['SecurityExecutionVersion']=copy.deepcopy(self.plan['template']['Resources'][self.plan['version_logical_id']])
        with self.assertRaises(StateError): prepare(current,self.package,object_version='different-object-version')

    def test_bad_package_mutable_storage_wrong_identity_or_enabled_runtime_rejected(self):
        for field,value in [('source_commit','main'),('sha256','invalid'),('code_sha256','unbound'),
                            ('zip_bytes',True),('zip_bytes',52428801)]:
            with self.subTest(field=field), self.assertRaises(StateError):
                prepare(self.current,{**self.package,field:value},object_version='v1')
        for version in ('null','',True,'bad version'):
            with self.assertRaises(StateError): prepare(self.current,self.package,object_version=version)
        for field,value in [('FunctionName','other'),('Runtime','python3.13'),('Role','arbitrary-role')]:
            current=copy.deepcopy(self.current); current['Resources']['SecurityFunction']['Properties'][field]=value
            with self.assertRaises(StateError): prepare(current,self.package,object_version='v1')
        current=copy.deepcopy(self.current)
        current['Resources']['SecurityFunction']['Properties']['Environment']['Variables']['FACTORY_OPERATIONAL_EXECUTION_ENABLED']='true'
        with self.assertRaises(StateError): prepare(current,self.package,object_version='v1')

    def test_replacement_deletion_protected_property_or_resource_rejected(self):
        mutations = [('Action','Remove'),('Replacement','True'),('Replacement','Conditional'),('Scope',['DeletionPolicy'])]
        for field,value in mutations:
            changes=copy.deepcopy(self.change_set); changes['Changes'][0]['ResourceChange'][field]=value
            with self.assertRaises(StateError): self.validate(changes)
        for name in ('Role','Runtime','MemorySize'):
            changes=copy.deepcopy(self.change_set)
            changes['Changes'][0]['ResourceChange']['Details'][0]['Target']['Name']=name
            with self.assertRaises(StateError): self.validate(changes)
        for name in ('SecurityVersion','SecurityRole','QaFunction'):
            changes=copy.deepcopy(self.change_set); changes['Changes'][1]['ResourceChange']['LogicalResourceId']=name
            with self.assertRaises(StateError): self.validate(changes)

    def test_actual_template_tampering_and_rehashed_plan_rejected(self):
        for field in ('SecurityRole','QaFunction','SecurityVersion'):
            proposed=copy.deepcopy(self.plan['template']); proposed['Resources'][field]['Metadata']={'changed':True}
            with self.assertRaises(StateError): self.validate(proposed=proposed)
        from prepare_security_validation_deployment import digest
        plan=copy.deepcopy(self.plan); plan['template']['Resources']['SecurityRole']['Properties']['Policies']=[]
        plan['template_digest']=digest(plan['template'])
        with self.assertRaises(StateError): self.validate(plan=plan,proposed=plan['template'])

    def test_parameters_incomplete_pages_duplicate_changes_and_wrong_stack_rejected(self):
        for change in ('parameters','missing-parameter','duplicate','extra','paged','stack','status','executed'):
            cs=copy.deepcopy(self.change_set)
            if change=='parameters': cs['Parameters'][0]={'ParameterKey':'ArtifactBucket','ParameterValue':'other'}
            elif change=='missing-parameter': cs['Parameters'].pop()
            elif change=='duplicate': cs['Changes'][1]=cs['Changes'][0]
            elif change=='extra': cs['Changes'].append(cs['Changes'][0])
            elif change=='paged': cs['NextToken']='more'
            elif change=='stack': cs['StackId']=self.stack+'different'
            elif change=='status': cs['Status']='CREATE_IN_PROGRESS'
            else: cs['ExecutionStatus']='EXECUTE_COMPLETE'
            with self.subTest(change=change),self.assertRaises(StateError): self.validate(cs)


if __name__=='__main__': unittest.main()
