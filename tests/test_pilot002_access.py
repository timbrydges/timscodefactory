import copy
import unittest
import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
import prepare_pilot002_access as p
from factory_state.model import StateError


class RuntimeAccessTests(unittest.TestCase):
    def setUp(self):
        self.base=p.baseline();self.template=p.render(self.base)
        self.preview={'Status':'CREATE_COMPLETE','ExecutionStatus':'AVAILABLE',
            'StackId':f'arn:aws:cloudformation:{p.REGION}:{p.ACCOUNT}:stack/{p.STACK}/fixture',
            'Changes':[{'Type':'Resource','ResourceChange':{'LogicalResourceId':r.title()+'Access',
                'Action':'Add','ResourceType':'AWS::IAM::Policy'}} for r in p.ROLES]}

    def test_existing_nine_resources_identical_and_three_separate_policies(self):
        for name,value in self.base['Resources'].items():self.assertEqual(self.template['Resources'][name],value)
        self.assertEqual(len(self.template['Resources']),12)
        self.assertEqual(p.validate_changes(self.template,self.preview)['new_policies'],3)

    def test_each_role_can_only_claim_and_update_its_permanent_attempt(self):
        for role in p.ROLES:
            statement=p.policy(role)['Statement'][0]
            self.assertEqual(statement['Action'],['dynamodb:PutItem','dynamodb:UpdateItem'])
            self.assertEqual(statement['Resource'],p.TABLE)
            self.assertEqual(statement['Condition'],{'ForAllValues:StringEquals':{
                'dynamodb:LeadingKeys':['PILOT#002#TASK#safe-workspace-fingerprint-001#ROLE#'+role]},
                'Null':{'dynamodb:LeadingKeys':'false'}})
            self.assertEqual(self.template['Resources'][role.title()+'Access']['Properties']['Roles'],
                ['tims-factory-pilot-002-'+role+'-disabled'])

    def test_secret_roles_have_one_exact_secret_and_scoped_builder_decryption(self):
        for role in ('builder','qa'):
            statements=p.policy(role)['Statement'];self.assertEqual(len(statements),3 if role=='builder' else 2)
            self.assertEqual(statements[1]['Action'],'secretsmanager:GetSecretValue')
            self.assertEqual(statements[1]['Resource'],p.SECRETS[role]);self.assertNotIn('*',statements[1]['Resource'])
        decrypt=p.policy('builder')['Statement'][2]
        self.assertEqual(decrypt['Action'],'kms:Decrypt');self.assertEqual(decrypt['Resource'],p.BUILDER_KEY)
        self.assertEqual(decrypt['Condition']['StringEquals'],{
            'kms:ViaService':'secretsmanager.ca-central-1.amazonaws.com',
            'kms:EncryptionContext:SecretARN':p.SECRETS['builder'],
            'kms:EncryptionContext:SecretVersionId':p.BUILDER_VERSION})

    def test_inspector_models_require_exact_profile_and_region(self):
        statements=p.policy('inspector')['Statement'][1:];self.assertEqual(len(statements),3)
        for statement in statements:
            self.assertEqual(statement['Action'],'bedrock:InvokeModel');self.assertNotIn('*',statement['Resource'])
        self.assertEqual(statements[0]['Resource'],p.PROFILE)
        for statement in statements[1:]:self.assertEqual(statement['Condition']['StringEquals']['bedrock:InferenceProfileArn'],p.PROFILE)
        self.assertEqual(statements[-1]['Condition']['StringEquals']['aws:RequestedRegion'],'unspecified')

    def test_changed_baseline_and_widened_candidate_rejected(self):
        changed=copy.deepcopy(self.base);changed['Resources']['BuilderFunction']['Properties']['ReservedConcurrentExecutions']=1
        with self.assertRaises(StateError):p.render(changed)
        changed=copy.deepcopy(self.template);changed['Resources']['BuilderAccess']['Properties']['PolicyDocument']['Statement'][0]['Resource']='*'
        with self.assertRaises(StateError):p.validate_changes(changed,self.preview)

    def test_extra_missing_duplicate_modify_wrong_account_and_pending_rejected(self):
        variants=[]
        for change in ({'NextToken':'more'},{'Status':'CREATE_PENDING'},{'ExecutionStatus':'EXECUTE_COMPLETE'},
                {'StackId':'wrong-account'},{'Parameters':[{}]}):variants.append({**self.preview,**change})
        x=copy.deepcopy(self.preview);x['Changes'][0]['ResourceChange']['Action']='Modify';variants.append(x)
        x=copy.deepcopy(self.preview);x['Changes'][0]=x['Changes'][1];variants.append(x)
        x=copy.deepcopy(self.preview);x['Changes'].pop();variants.append(x)
        x=copy.deepcopy(self.preview);x['Changes'].append(x['Changes'][0]);variants.append(x)
        for value in variants:
            with self.subTest(value=value),self.assertRaises(StateError):p.validate_changes(self.template,value)


if __name__=='__main__':unittest.main()
