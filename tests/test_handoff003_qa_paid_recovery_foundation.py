import copy,unittest
import prepare_handoff003_qa_paid_recovery_foundation as f
from factory_state.model import StateError

class RecoveryFoundationTests(unittest.TestCase):
    def setUp(self):
        self.args=dict(source_commit='a'*40,code=dict(S3Bucket='reviewed-bucket',S3Key='recovery.zip',S3ObjectVersion='immutable-version'))
        self.template=f.render(**self.args)
        self.change=dict(Status='CREATE_COMPLETE',ExecutionStatus='AVAILABLE',StackId=f'arn:aws:cloudformation:{f.REGION}:{f.ACCOUNT}:stack/{f.STACK}/id',
            Changes=[dict(Type='Resource',ResourceChange=dict(LogicalResourceId=k,ResourceType=v['Type'],Action='Add')) for k,v in self.template['Resources'].items()])
    def test_disabled_worker_and_isolated_permanent_claim(self):
        self.assertEqual(f.validate_changes(self.template,self.change,**self.args)['reserved_concurrency'],0)
        resources=self.template['Resources'];fn=resources['QaFunction']['Properties'];table=resources['Attempts']
        self.assertEqual(fn['ReservedConcurrentExecutions'],0);self.assertEqual(fn['Timeout'],240)
        self.assertEqual(fn['Environment']['Variables'],{f.ENABLED:'false'})
        self.assertTrue(table['Properties']['DeletionProtectionEnabled']);self.assertEqual(table['DeletionPolicy'],'Retain')
        self.assertNotIn('TimeToLiveSpecification',table['Properties'])
        statements=f.policy()['Statement'];row=statements[0]
        self.assertTrue(row['Resource'].endswith('/'+f.TABLE));self.assertEqual(row['Condition']['ForAllValues:StringEquals']['dynamodb:LeadingKeys'],[f.PK])
        for s in statements:self.assertTrue(s['Condition']['ArnEquals']['lambda:SourceFunctionArn'].endswith(':'+f.NAME))
    def test_existing_resource_mutation_partial_preview_or_enabled_worker_rejected(self):
        for field,value in [('Action','Modify'),('Action','Remove'),('ResourceType','AWS::Events::Rule')]:
            bad=copy.deepcopy(self.change);bad['Changes'][0]['ResourceChange'][field]=value
            with self.assertRaises(StateError):f.validate_changes(self.template,bad,**self.args)
        bad=copy.deepcopy(self.template);bad['Resources']['QaFunction']['Properties']['ReservedConcurrentExecutions']=1
        with self.assertRaises(StateError):f.validate_changes(bad,self.change,**self.args)
        with self.assertRaises(StateError):f.validate_changes(self.template,{**self.change,'NextToken':'more'},**self.args)

if __name__=='__main__':unittest.main()
