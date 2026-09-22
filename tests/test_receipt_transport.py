import base64
import io
import json
import sys
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT));sys.path.insert(0,str(ROOT/'src'))
from factory_runtime.intake import IntakePlan
from factory_runtime.receipt_transport import (ReceiptVersions, VersionedS3ReceiptTransport,
                                               receipt_plan_digest)
from factory_state.dispatch import DispatchRequest, DynamoDBDispatchStore
from factory_state.model import Lease, StateError

NOW=datetime(2026,9,22,20,tzinfo=timezone.utc)


def plan():
    lease=Lease('auto-'+'1'*24,'engineering_agent','engineering_agent_service',NOW+timedelta(minutes=15))
    request=DispatchRequest(lease.lease_id,'autonomy','cycle','a'*40,'sha256:'+'b'*64,'sha256:'+'c'*64)
    times={'issued_at':int(NOW.timestamp()),'expires_at':int(NOW.timestamp())+600}
    capability={'kind':'capability','factory_id':'factory','objective_id':'autonomy','capability_id':'cycle',
        'contract_digest':request.contract_digest,'owner_identity':'tim_brydges','required_evidence':'signed result',
        'stop_condition':'one gate','issued_at':times['issued_at'],'expires_at':times['expires_at']}
    review={'kind':'scope_review','factory_id':'factory','task_id':'task-1',
        'binding':DynamoDBDispatchStore._binding(request),'verdict':'ACCEPTED',
        'reviewer_identity':'independent_inspector_service','rationale':'reviewed',**times}
    return IntakePlan('factory','task-1','IMPLEMENTATION',4,lease,request,capability,review)


class Body(io.BytesIO):
    pass


class FakeConfig:
    retries={'total_max_attempts':1}


class FakeMeta:
    endpoint_url='https://s3.ca-central-1.amazonaws.com'
    config=FakeConfig()


class FakeS3:
    def __init__(self,documents): self.documents=documents;self.calls=[];self.meta=FakeMeta()
    def get_object(self,**request):
        self.calls.append(request);raw=self.documents[(request['Key'],request['VersionId'])]
        digest=request['Key'].split('/')[1]
        return {'VersionId':request['VersionId'],'ContentLength':len(raw),
            'Metadata':{'plan-digest':'sha256:'+digest},
            'ChecksumSHA256':base64.b64encode(__import__('hashlib').sha256(raw).digest()).decode(),
            'Body':Body(raw)}


class ReceiptTransportTests(unittest.TestCase):
    def envelopes(self,current):
        digest_value=receipt_plan_digest(current);root=f'factory-scope-receipts/{digest_value[7:]}'
        owner={'schema_version':'1.0','plan_digest':digest_value,'signer_identity':'tim_brydges',
            'payload':current.capability_payload,'signature_base64':base64.b64encode(b'o'*64).decode()}
        reviewer={'schema_version':'1.0','plan_digest':digest_value,
            'signer_identity':'independent_inspector_service','payload':current.review_payload,
            'signature_base64':base64.b64encode(b'r'*64).decode()}
        return digest_value,{(root+'/owner.json','v-owner'):json.dumps(owner).encode(),
            (root+'/reviewer.json','v-review'):json.dumps(reviewer).encode()}

    def test_loads_only_exact_versioned_plan_bound_receipts(self):
        current=plan();digest_value,documents=self.envelopes(current);client=FakeS3(documents)
        bundle=VersionedS3ReceiptTransport(client).load(current,ReceiptVersions('v-owner','v-review'))
        self.assertEqual(bundle.plan_digest,digest_value);self.assertEqual(bundle.owner_signature,b'o'*64)
        self.assertEqual(bundle.reviewer_signature,b'r'*64);self.assertEqual(len(client.calls),2)
        self.assertTrue(all(call['ChecksumMode']=='ENABLED' for call in client.calls))

    def test_changed_payload_version_or_signature_fails_closed(self):
        current=plan();_,documents=self.envelopes(current);key=next(iter(documents))
        envelope=json.loads(documents[key]);envelope['payload']['required_evidence']='changed'
        documents[key]=json.dumps(envelope).encode()
        with self.assertRaises(StateError):
            VersionedS3ReceiptTransport(FakeS3(documents)).load(current,ReceiptVersions('v-owner','v-review'))
        with self.assertRaises(StateError): ReceiptVersions('', 'v-review')


if __name__=='__main__':unittest.main()
