"""Durable simulated intake with actual QA, owner and independent signatures."""
import unittest

import test_security_scope_integration as fixtures
from test_security_provider_claims import mock_aws
from factory_runtime.intake import AuthenticatedIntakeService
from factory_runtime.security_scope_policy import SecurityScopeSigner
from factory_state.dynamodb import DynamoDBStateStore
from factory_state.dispatch import DynamoDBDispatchStore
from factory_state.model import StateError


@unittest.skipIf(mock_aws is None,'Requires moto[dynamodb]')
class SecurityIntakeTests(unittest.TestCase):
    def setUp(self):
        import boto3
        from botocore.config import Config
        aws=mock_aws();aws.start();self.addCleanup(aws.stop)
        f=fixtures.SignedQAScopeTests();f.setUp();self.addCleanup(f.doCleanups)
        self.f=f;self.policy=f.policy;p=f.policy.prerequisites
        self.db=boto3.client('dynamodb',region_name='ca-central-1',config=Config(retries={'total_max_attempts':1}))
        self.table='security-intake-fixture'
        self.db.create_table(TableName=self.table,KeySchema=[{'AttributeName':'PK','KeyType':'HASH'},
            {'AttributeName':'SK','KeyType':'RANGE'}],AttributeDefinitions=[{'AttributeName':k,'AttributeType':'S'}
                for k in ('PK','SK')],BillingMode='PAY_PER_REQUEST')
        state=p.states.load_state(p.qa_binding.factory_id,p.qa_binding.task_id)
        self.states=DynamoDBStateStore(self.table,self.db);self.ledger=DynamoDBDispatchStore(self.table,self.db)
        item=self.states._serialize_state(state);item['SK']={'S':'STATE'}
        self.db.put_item(TableName=self.table,Item=item)
        for lease in state.leases:
            self.db.put_item(TableName=self.table,Item=self.states._serialize_lease(state,lease))
        self.qa_key=self.ledger._key(state,p.request)
        self.qa_row={**self.qa_key,**f.row,'binding':{'S':self.ledger._binding(p.request)}}
        self.db.put_item(TableName=self.table,Item=self.qa_row)
        p.states=self.states;p.ledger=self.ledger
        self.intake=AuthenticatedIntakeService(self.states,self.ledger,
            key_loader=lambda _:f.f.keys,clock=lambda:f.f.now)

    def reviewer_signature(self):
        return SecurityScopeSigner(policy=self.policy,kms=self.f,sts=self.f,enabled=True).sign(
            self.f.payload,now=self.f.f.now)

    def activate(self, signature):
        return self.intake.activate(self.policy.plan,owner_signature=self.policy.owner_signature,
            reviewer_signature=signature)

    def test_signed_intake_queues_once_and_preserves_historical_qa(self):
        signature=self.reviewer_signature()
        first=self.activate(signature);second=self.activate(signature)
        self.assertEqual((first['status'],second['status']),('QUEUED','ALREADY_QUEUED'))
        self.assertEqual(first['dispatch_id'],second['dispatch_id'])
        self.assertEqual(first['model_calls'],0)
        p=self.policy.plan;state=self.states.load_state(p.factory_id,p.task_id)
        self.assertEqual((state.state,state.version),('SECURITY_REVIEW',8))
        self.assertEqual(self.db.get_item(TableName=self.table,Key=self.qa_key)['Item'],self.qa_row)
        self.assertEqual(self.ledger.read(state,p.request)['status'],{'S':'READY'})

    def test_invalid_review_signature_cannot_issue_lease_or_queue(self):
        p=self.policy.plan;before=self.states.load_state(p.factory_id,p.task_id)
        with self.assertRaises(StateError):self.activate(b'x'*64)
        self.assertEqual(self.states.load_state(p.factory_id,p.task_id),before)
        self.assertIsNone(self.ledger.read(before,p.request))


if __name__ == '__main__':unittest.main()
