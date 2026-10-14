"""Full file-to-role boundary: real signatures, Moto storage, simulated HTTPS."""
import base64
from dataclasses import asdict
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import test_security_intake_integration as intake_fixture
import test_security_signing as signing_fixture
from test_security_provider_claims import mock_aws
from test_security_provider_scope import fixture as allowance_fixture
from test_pilot002_transport import Connection, Response, AWS
from factory_runtime import security_role_lambda as entry, pilot002_transport as wire
from factory_runtime.security_provider_claims import SecurityProviderClaims
from factory_runtime.review_provider_claims import TABLE
from factory_runtime.security_provider_scope import verify
from factory_runtime.worker import digest
from factory_state.dynamodb import DynamoDBStateStore
from factory_state.dispatch import DynamoDBDispatchStore
from factory_state.model import CONTROLLER_IDENTITY, StateError
from factory_state.scope import canonical
from factory_state.signers import public_key_der
from scripts.scope_dispatch_canary import sign


@unittest.skipIf(mock_aws is None,'Requires moto[dynamodb]')
class EntryCycleTests(unittest.TestCase):
    def setUp(self):
        t=intake_fixture.SecurityIntakeTests();t.setUp();self.addCleanup(t.doCleanups)
        self.t=t;policy=t.policy;self.now=t.f.f.now;self.material=policy.material
        queued=t.activate(t.reviewer_signature());self.dispatch_id=queued['dispatch_id']
        s=signing_fixture.SecuritySigningTests();s.setUp();self.addCleanup(s.doCleanups);self.signing=s
        keys=dict(t.f.f.keys);keys['deep_security_reviewer_service']=s.keys['deep_security_reviewer_service']
        self.root=Path(t.f.f.temp.name)
        self.env={'FACTORY_SECURITY_ENABLED':'true','AWS_REGION':'ca-central-1','AWS_LAMBDA_FUNCTION_NAME':entry.NAME}
        def pinned(name,pin,value):
            raw=canonical(value);(self.root/name).write_bytes(raw);self.env[pin]=digest(raw)
        (self.root/'BUILD.json').write_bytes(canonical({'source_commit':self.material.binding.qa.source_commit}))
        raw=t.f.f.f.f.raw
        (self.root/'REVIEW_MATERIAL.json').write_bytes(raw);self.env['FACTORY_SECURITY_MATERIAL_DIGEST']=digest(raw)
        prior=policy.prerequisites
        pinned('SECURITY_QA.json','FACTORY_SECURITY_QA_DIGEST',{'kind':'bounded_security004_qa_provenance',
            'qa_binding':asdict(prior.qa_binding),'qa_request':asdict(prior.request),
            'qa_result_digest':self.material.binding.qa_result_digest})
        for historical in (False,True):
            selected={'qa_engineer_service':keys['qa_engineer_service']} if historical else keys
            registry={'schema_version':'1.0','enabled':True,'signers':[{
                'identity':i,'public_key_pem':pem.decode(),'fingerprint':digest(public_key_der(pem)),
                'enrollment_commit':'a'*40,'not_before':int(self.now.timestamp())-10000,
                'expires_at':int(self.now.timestamp())+3600,'revoked':False} for i,pem in selected.items()]}
            pinned('SECURITY_QA_SIGNERS.json' if historical else 'SECURITY_SIGNERS.json',
                'FACTORY_SECURITY_QA_SIGNERS_DIGEST' if historical else 'FACTORY_SECURITY_SIGNERS_DIGEST',registry)
        prepared=self.material.prepared();scope=prepared.scope
        _,price,ready,payload=allowance_fixture()
        for doc in (price,ready,payload):
            doc.update(scope.bindings(),issued_at=int(self.now.timestamp())-1,expires_at=int(self.now.timestamp())+600)
        payload.update(pricing_digest=digest(canonical(price)),readiness_digest=digest(canonical(ready)))
        envelope={'payload':payload,'signature_base64':base64.b64encode(
            sign(payload,t.f.f.private['tim_brydges'],t.f.f.temp.name)).decode()}
        pinned('SECURITY_ALLOWANCE.json','FACTORY_SECURITY_ALLOWANCE_DIGEST',
            {'allowance':envelope,'pricing':price,'readiness':ready})
        db=t.db
        for name in ('tims-software-factory-state','tims-factory-role-executions'):
            db.create_table(TableName=name,KeySchema=[{'AttributeName':'PK','KeyType':'HASH'},
                {'AttributeName':'SK','KeyType':'RANGE'}],AttributeDefinitions=[{'AttributeName':k,'AttributeType':'S'}
                    for k in ('PK','SK')],BillingMode='PAY_PER_REQUEST')
        for row in db.scan(TableName=t.table)['Items']:db.put_item(TableName='tims-software-factory-state',Item=row)
        db.create_table(TableName=TABLE,KeySchema=[{'AttributeName':'PK','KeyType':'HASH'}],
            AttributeDefinitions=[{'AttributeName':'PK','AttributeType':'S'}],BillingMode='PAY_PER_REQUEST')
        states=DynamoDBStateStore('tims-software-factory-state',db)
        ledger=DynamoDBDispatchStore('tims-software-factory-state',db)
        q=self.material.binding.qa;state=states.load_state(q.factory_id,q.task_id)
        if getattr(self,'preclaim',True):
            ledger.claim(state,scope.request,worker_id='bounded-security-controller',caller_identity=CONTROLLER_IDENTITY,now=self.now)
            SecurityProviderClaims(db).hold(verify(envelope,scope=scope,pricing=price,readiness=ready,
                trusted_keys=keys,now=self.now),self.dispatch_id,now=self.now)
        def meta(service):return SimpleNamespace(endpoint_url=f'https://{service}.ca-central-1.amazonaws.com',
            config=SimpleNamespace(retries={'total_max_attempts':1}))
        clients={'dynamodb':db,'sts':SimpleNamespace(meta=meta('sts'),get_caller_identity=s.get_caller_identity),
            'kms':SimpleNamespace(meta=meta('kms'),get_public_key=s.get_public_key,sign=s.sign)}
        self.session=SimpleNamespace(client=lambda service,**kwargs:clients[service],
            get_credentials=lambda:SimpleNamespace(get_frozen_credentials=lambda:AWS))
        self.event={'schema_version':'1.0','factory_id':q.factory_id,'task_id':q.task_id,
            'worker_id':'bounded-security-controller','request':asdict(scope.request),'dispatch_id':self.dispatch_id,
            'input_base64':base64.b64encode(prepared.input_bytes).decode()}
        self.context=SimpleNamespace(invoked_function_arn=
            'arn:aws:lambda:ca-central-1:666730517561:function:'+entry.NAME+':1',get_remaining_time_in_millis=lambda:180000)
        report={**json.loads(prepared.expected_output),'verdict':'ACCEPTED','rationale':'Fixture only.','findings':[]}
        self.response=canonical({'stopReason':'end_turn','output':{'message':{'role':'assistant',
            'content':[{'text':canonical(report).decode()}]}},'usage':{'inputTokens':100,'outputTokens':50,'totalTokens':150}})

    def test_full_entrypoint_and_replay_send_and_sign_only_once(self):
        with patch.object(entry,'_aws_session',return_value=self.session), \
                patch.object(wire.http.client,'HTTPSConnection',return_value=Connection(Response(self.response))) as network:
            first=entry.dispatch(self.event,self.context,root=self.root,env=self.env,clock=lambda:self.now)
            second=entry.dispatch(self.event,self.context,root=self.root,env=self.env,clock=lambda:self.now)
        self.assertEqual(first,second);self.assertEqual(network.call_count,1);self.assertEqual(self.signing.calls,1)
        row=self.t.db.get_item(TableName=TABLE,Key={'PK':{'S':'BOUNDED_SECURITY#004#ROLE#security'}})['Item']
        self.assertEqual(row['status'],{'S':'COMPLETE'});self.assertEqual(row['reservation_status'],{'S':'HELD'})

    def test_uncertain_provider_send_keeps_claim_and_cannot_retry(self):
        with patch.object(entry,'_aws_session',return_value=self.session), \
                patch.object(wire.http.client,'HTTPSConnection',return_value=Connection(error=TimeoutError('fixture'))) as network:
            for _ in range(2):
                with self.assertRaises(StateError):
                    entry.dispatch(self.event,self.context,root=self.root,env=self.env,clock=lambda:self.now)
        self.assertEqual(network.call_count,1);self.assertEqual(self.signing.calls,0)
        row=self.t.db.get_item(TableName=TABLE,Key={'PK':{'S':'BOUNDED_SECURITY#004#ROLE#security'}})['Item']
        self.assertEqual(row['status'],{'S':'STARTED'});self.assertEqual(row['reservation_status'],{'S':'HELD'})


if __name__ == '__main__':unittest.main()
