import unittest
from prepare_handoff004_dispatcher import render,policy,validate_changes,STACK
from factory_state.model import StateError


class DispatcherInfrastructureTests(unittest.TestCase):
    def test_no_implicit_invoke_provider_or_delete_authority(self):
        document=policy({});actions=[a for s in document['Statement'] for a in s['Action']]
        self.assertNotIn('lambda:InvokeFunction',actions)
        self.assertEqual(set(actions),{'dynamodb:GetItem','dynamodb:PutItem','dynamodb:UpdateItem',
            'logs:CreateLogStream','logs:PutLogEvents'})
        arn='arn:aws:lambda:ca-central-1:666730517561:function:tims-factory-handoff-004-builder:2'
        self.assertEqual(policy({'builder':arn})['Statement'][-1]['Resource'],[arn])
        for wrong in (arn.replace(':2',':latest'),arn.replace('004','003'),arn.replace(':2',':*')):
            with self.assertRaises(StateError):policy({'builder':wrong})
    def test_disabled_foundation_and_new_resources_only(self):
        args={'source_commit':'a'*40,'code':{'S3Bucket':'bucket','S3Key':'code','S3ObjectVersion':'v1'}}
        template=render(**args);resources=template['Resources']
        self.assertEqual(resources['Function']['Properties']['ReservedConcurrentExecutions'],0)
        self.assertTrue(resources['DispatchLedger']['Properties']['DeletionProtectionEnabled'])
        self.assertEqual(resources['DispatchLedger']['DeletionPolicy'],'Retain')
        preview={'Status':'CREATE_COMPLETE','ExecutionStatus':'AVAILABLE',
            'StackId':'arn:aws:cloudformation:ca-central-1:666730517561:stack/'+STACK+'/fixture',
            'Changes':[{'Type':'Resource','ResourceChange':{'LogicalResourceId':n,'ResourceType':v['Type'],'Action':'Add'}} for n,v in resources.items()]}
        self.assertEqual(validate_changes(template,preview,**args)['worker_invoke_permissions'],0)
        preview['Changes'][0]['ResourceChange']['Action']='Modify'
        with self.assertRaises(StateError):validate_changes(template,preview,**args)
