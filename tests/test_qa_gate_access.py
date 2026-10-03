import copy
import unittest
from datetime import datetime, timedelta, timezone
from prepare_qa_gate_access import prepare,validate_changes,LOG_POLICY,ROLE,TABLE,PARTITION,TRUST_END
from factory_state.model import StateError


class QaGateAccessTests(unittest.TestCase):
    def setUp(self):
        self.now=datetime(2026,10,3,13,tzinfo=timezone.utc)
        self.before={'Resources':{
            'ControllerRole':{'Type':'AWS::IAM::Role','Properties':{'RoleName':ROLE,
                'AssumeRolePolicyDocument':{'Version':'2012-10-17','Statement':[{
                    'Effect':'Allow','Principal':{'Service':'lambda.amazonaws.com'},'Action':'sts:AssumeRole'}]},
                'Policies':[copy.deepcopy(LOG_POLICY)]}},
            'ControllerFunction':{'Type':'AWS::Lambda::Function','Properties':{
                'FunctionName':'tims-software-factory-autonomy-controller',
                'Handler':'factory_runtime.qa_gate_runtime.controller_handler',
                'Role':{'Fn::GetAtt':['ControllerRole','Arn']},'ReservedConcurrentExecutions':0,
                'Environment':{'Variables':{'FACTORY_AUTONOMY_CONTROLLER_ENABLED':'false','FACTORY_QA_GATE_ENABLED':'false'}}}},
            'AcceptanceAlias':{'Type':'AWS::Lambda::Alias','Properties':{'FunctionVersion':'32'}}},
            'Outputs':{'Preserved':{'Value':'unchanged'}}}
        self.plan=prepare(self.before,starts_at=self.now,expires_at=self.now+timedelta(hours=1))
        self.changes={'StackId':'arn:aws:cloudformation:ca-central-1:666730517561:stack/tims-factory-autonomy-controller-disabled/test',
            'Status':'CREATE_COMPLETE','ExecutionStatus':'AVAILABLE','Parameters':[],
            'Changes':[{'Type':'Resource','ResourceChange':{'LogicalResourceId':'ControllerRole','Action':'Modify',
                'ResourceType':'AWS::IAM::Role','Replacement':'False','Scope':['Properties'],'Details':[{
                    'Target':{'Attribute':'Properties','Name':'Policies','RequiresRecreation':'Never'}}]}}]}

    def validate(self,**kwargs):
        return validate_changes(self.plan,self.before,self.plan['template'],self.changes,current_parameters={},**kwargs)

    def test_only_inline_policy_added_and_restore_is_exact(self):
        after=copy.deepcopy(self.plan['template'])
        added=after['Resources']['ControllerRole']['Properties']['Policies'].pop()
        self.assertEqual(after,self.before)
        self.assertEqual(self.plan['restore_template'],self.before)
        statement,=added['PolicyDocument']['Statement']
        self.assertEqual(statement['Action'],['dynamodb:GetItem','dynamodb:PutItem','dynamodb:UpdateItem'])
        self.assertEqual(statement['Resource'],TABLE)
        self.assertEqual(statement['Condition']['ForAllValues:StringEquals']['dynamodb:LeadingKeys'],[PARTITION])
        self.assertEqual(statement['Condition']['Null'],{'dynamodb:LeadingKeys':'false'})
        self.validate()
        validate_changes(self.plan,self.plan['template'],self.before,self.changes,current_parameters={},reverse=True)

    def test_expansion_via_template_or_plan_tampering_is_rejected(self):
        for target in ('template','policy'):
            original=copy.deepcopy(self.plan)
            policy=self.plan['template']['Resources']['ControllerRole']['Properties']['Policies'][-1] if target=='template' else self.plan['policy']
            policy['PolicyDocument']['Statement'][0]['Resource']='*'
            with self.assertRaises(StateError): self.validate()
            self.plan=original
        self.plan['template']['Resources']['AcceptanceAlias']['Properties']['FunctionVersion']='34'
        with self.assertRaises(StateError): self.validate()

    def test_unexpected_resource_replacement_or_parameter_edit_rejected(self):
        original=copy.deepcopy(self.changes)
        for field,value in [('Action','Add'),('Replacement','True'),('LogicalResourceId','SecurityRole')]:
            self.changes=copy.deepcopy(original)
            self.changes['Changes'][0]['ResourceChange'][field]=value
            with self.assertRaises(StateError): self.validate()
        self.changes=copy.deepcopy(original)
        self.changes['Parameters']=[{'ParameterKey':'CodeSha256','ParameterValue':'changed'}]
        with self.assertRaises(StateError): self.validate()

    def test_only_logging_only_disabled_controller_is_eligible(self):
        for change in ('managed','enabled','concurrency','trust'):
            modified=copy.deepcopy(self.before)
            props=modified['Resources']['ControllerRole']['Properties']
            if change=='managed': props['ManagedPolicyArns']=['arn:aws:iam::aws:policy/AdministratorAccess']
            elif change=='trust': props['AssumeRolePolicyDocument']['Statement'][0]['Principal']={'AWS':'*'}
            elif change=='enabled': modified['Resources']['ControllerFunction']['Properties']['Environment']['Variables']['FACTORY_QA_GATE_ENABLED']='true'
            else: modified['Resources']['ControllerFunction']['Properties']['ReservedConcurrentExecutions']=1
            with self.assertRaises(StateError): prepare(modified,starts_at=self.now,expires_at=self.now+timedelta(hours=1))

    def test_time_window_cannot_exceed_hour_or_enrollment(self):
        for start,end in ((self.now,self.now),(self.now,self.now+timedelta(seconds=3601)),
                          (TRUST_END-timedelta(minutes=1),TRUST_END+timedelta(seconds=1)),
                          (self.now.replace(tzinfo=None),self.now+timedelta(minutes=1))):
            with self.assertRaises(StateError): prepare(self.before,starts_at=start,expires_at=end)

    def test_function_environment_change_not_hidden_by_role_dependency(self):
        change=copy.deepcopy(self.changes['Changes'][0])
        rc=change['ResourceChange']; rc.update(LogicalResourceId='ControllerFunction',ResourceType='AWS::Lambda::Function')
        rc['Details'][0]['Target']['Name']='Role'
        self.changes['Changes'].append(change)
        self.validate()
        rc['Details'][0]['Target']['Name']='Environment'
        with self.assertRaises(StateError): self.validate()


if __name__=='__main__': unittest.main()
