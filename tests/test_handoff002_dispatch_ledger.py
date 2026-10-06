import copy
import unittest
from prepare_handoff002_dispatch_ledger import render, validate_changes, STACK
from factory_state.model import StateError


class LedgerTests(unittest.TestCase):
    def setUp(self):
        self.preview={'Status':'CREATE_COMPLETE','ExecutionStatus':'AVAILABLE',
            'StackId':'arn:aws:cloudformation:ca-central-1:666730517561:stack/'+STACK+'/test',
            'Changes':[{'Type':'Resource','ResourceChange':{'LogicalResourceId':'DispatchLedger',
                'ResourceType':'AWS::DynamoDB::Table','Action':'Add'}}]}

    def test_no_expiry_deletion_or_execution_authority(self):
        template=render(); resource=template['Resources']['DispatchLedger']
        self.assertEqual(resource['DeletionPolicy'],'Retain')
        self.assertEqual(resource['UpdateReplacePolicy'],'Retain')
        self.assertTrue(resource['Properties']['DeletionProtectionEnabled'])
        self.assertNotIn('TimeToLiveSpecification',resource['Properties'])
        self.assertEqual(validate_changes(template,self.preview)['execution_permissions'],0)

    def test_existing_changes_pagination_and_disabled_protection_rejected(self):
        for action in ('Modify','Remove'):
            preview=copy.deepcopy(self.preview)
            preview['Changes'][0]['ResourceChange']['Action']=action
            with self.assertRaises(StateError):validate_changes(render(),preview)
        with self.assertRaises(StateError):validate_changes(render(),{**self.preview,'NextToken':'more'})
        altered=render();altered['Resources']['DispatchLedger']['Properties']['DeletionProtectionEnabled']=False
        with self.assertRaises(StateError):validate_changes(altered,self.preview)
