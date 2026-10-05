import base64
import copy
import hashlib
import json
import sys
import unittest
from datetime import datetime,timedelta,timezone
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'scripts'),str(ROOT/'src')]
import prepare_qa_recovery001_live as p
import test_qa_recovery001_activation_package as fixtures
from factory_state.model import StateError
from factory_state.scope import canonical


class RecoveryLivePreviewTests(unittest.TestCase):
    def setUp(self):
        fixture=fixtures.RecoveryActivationPackageTests();fixture.setUp()
        self.raw=canonical(fixture.doc);self.now=fixture.now
        material=p.validate_material(fixture.files,self.raw,self.now)
        sha=hashlib.sha256(b'synthetic package').digest()
        self.package={'source_commit':fixture.doc['source_commit'],'sha256':sha.hex(),
            'code_sha256':base64.b64encode(sha).decode(),'zip_bytes':100,
            'handler':'factory_runtime.qa_recovery001_entrypoint.handler',
            'execution_enabled':False,'activation_included':True,'signed_allowance_included':False,'model_calls':0,**material}
        self.code={'S3Bucket':p.disabled.BUCKET,'S3Key':'qa-recovery-001/runtime/'+self.package['source_commit']+'/'+sha.hex()+'.zip',
            'S3ObjectVersion':'synthetic-immutable-version'}
        self.args={'activation':self.raw,'now':self.now,'shared_capacity_approved':True}
        self.template=p.render(p.baseline(),self.package,self.code,**self.args)
        self.changes={'Status':'CREATE_COMPLETE','ExecutionStatus':'AVAILABLE','StackId':p.STACK,
            'Changes':[{'Type':'Resource','ResourceChange':{'LogicalResourceId':'RecoveryAccess','Action':'Add','ResourceType':'AWS::IAM::Policy'}},
                {'Type':'Resource','ResourceChange':{'LogicalResourceId':'RecoveryFunction','Action':'Modify','ResourceType':'AWS::Lambda::Function','Replacement':'False'}}]}

    def test_exact_recovery_only_permissions_and_unchanged_rollback(self):
        before=p.baseline()
        result=p.validate(self.template,self.changes,self.package,self.code,**self.args)
        self.assertEqual(result['maximum_provider_calls'],1);self.assertEqual(result['model_calls'],0)
        self.assertEqual(p.baseline(),before)
        for name in ('RecoveryRole','RecoveryLogs'):self.assertEqual(self.template['Resources'][name],before['Resources'][name])
        function=self.template['Resources']['RecoveryFunction']['Properties']
        self.assertNotIn('ReservedConcurrentExecutions',function)
        self.assertEqual(function['Environment']['Variables']['FACTORY_QA_RECOVERY001_ENABLED'],'true')
        statements=self.template['Resources']['RecoveryAccess']['Properties']['PolicyDocument']['Statement']
        self.assertEqual(statements[0]['Action'],['dynamodb:PutItem','dynamodb:UpdateItem'])
        self.assertEqual(statements[0]['Condition']['ForAllValues:StringEquals']['dynamodb:LeadingKeys'],[p.PK])
        self.assertEqual(statements[0]['Condition']['Null']['dynamodb:LeadingKeys'],'false')
        self.assertTrue(statements[0]['Resource'].endswith('/'+p.TABLE))
        self.assertEqual(len(statements),2)
        self.assertEqual(statements[1]['Action'],'secretsmanager:GetSecretValue')
        self.assertEqual(statements[1]['Resource'],p.GOOGLE_ROUTE['secret_arn'])
        self.assertEqual(statements[1]['Condition'],{'StringEquals':{'secretsmanager:VersionId':p.GOOGLE_ROUTE['version_id']}})
        self.assertNotIn('pilot-002-attempts',json.dumps(self.template))
        self.assertNotIn('bedrock:',json.dumps(self.template))

    def test_requires_explicit_shared_capacity_and_exact_baseline(self):
        for approval in (False,None,1,'true'):
            with self.assertRaises(StateError):p.render(p.baseline(),self.package,self.code,**{**self.args,'shared_capacity_approved':approval})
        bad=p.baseline();bad['Resources']['RecoveryFunction']['Properties']['Timeout']=181
        with self.assertRaises(StateError):p.render(bad,self.package,self.code,**self.args)

    def test_changed_package_activation_code_and_expiry_rejected(self):
        for update in ({'activation_sha256':'0'*64},{'request_digest':'sha256:'+'0'*64},
                       {'activation_authorized':True},{'execution_enabled':True},{'signed_allowance_included':True},
                       {'activation_included':False},{'model_calls':True},{'material_expires_at':True},
                       {'maximum_cost_micro_usd':250001},{'zip_bytes':5000001},{'extra':'override'}):
            with self.subTest(update=update),self.assertRaises(Exception):p.render(p.baseline(),{**self.package,**update},self.code,**self.args)
        for update in ({'S3ObjectVersion':'null'},{'S3Bucket':'other'},{'S3Key':'latest.zip'}):
            with self.assertRaises(Exception):p.render(p.baseline(),self.package,{**self.code,**update},**self.args)
        for when in (self.now+timedelta(hours=2),datetime.fromtimestamp(self.package['material_expires_at']-59,timezone.utc)):
            with self.assertRaises(Exception):p.render(p.baseline(),self.package,self.code,**{**self.args,'now':when})
        with self.assertRaises(Exception):p.render(p.baseline(),self.package,self.code,**{**self.args,'activation':b'{}'})

    def test_expanded_permissions_and_unrelated_or_replaced_resources_rejected(self):
        for mutate in (lambda t:t['Resources']['RecoveryAccess']['Properties']['PolicyDocument']['Statement'][0].update(Resource='*'),
                       lambda t:t['Resources']['RecoveryRole']['Properties'].update(ManagedPolicyArns=['AdministratorAccess']),
                       lambda t:t['Resources']['RecoveryFunction']['Properties'].update(Timeout=900)):
            value=copy.deepcopy(self.template);mutate(value)
            with self.assertRaises(StateError):p.validate(value,self.changes,self.package,self.code,**self.args)
        for mutate in (lambda c:c.update(NextToken='more'),lambda c:c.update(StackId='other'),
                       lambda c:c['Changes'][0]['ResourceChange'].update(Action='Modify'),
                       lambda c:c['Changes'][1]['ResourceChange'].update(Replacement='True'),
                       lambda c:c['Changes'][0]['ResourceChange'].update(LogicalResourceId='RecoveryLogs'),
                       lambda c:c['Changes'].append(copy.deepcopy(c['Changes'][0]))):
            value=copy.deepcopy(self.changes);mutate(value)
            with self.assertRaises(StateError):p.validate(self.template,value,self.package,self.code,**self.args)


if __name__=='__main__':unittest.main()
