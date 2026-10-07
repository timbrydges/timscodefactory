"""Full security cycle with real fixture signatures; simulated AWS/HTTPS only."""
import base64
import copy
from dataclasses import replace
from datetime import timedelta
import io
import json
import unittest
from unittest.mock import Mock, patch

from factory_runtime import pilot002_transport as wire
from factory_runtime.acceptance_jobs import PinnedJobVersion
from factory_runtime.autonomy import AutonomyActivation, ScheduledAutonomyJob
from factory_runtime.intake import IntakePlan
from factory_runtime.receipt_transport import ReceiptVersions
from factory_runtime.security_controller import BoundedSecurityController
from factory_runtime.security_provider_protocol import prepare, job_input
from factory_runtime.security_qa_provenance import ConsumedQAProvenance
from factory_runtime.worker import digest
from factory_state.model import CONTROLLER_IDENTITY, Lease, StateError
from factory_state.scope import SignedScopeStore, canonical
from scripts.scope_dispatch_canary import fixture_keys, sign
import test_security_role_integration as role_fixtures
from test_security_provider_claims import mock_aws, NOW
from test_pilot002_transport import Connection, Response
from test_review_controller import NoIO


@unittest.skipIf(mock_aws is None,'Requires moto[dynamodb]')
class FullSecurityCycleTests(unittest.TestCase):
    def setUp(self):
        f=role_fixtures.SecurityRoleIntegrationTests();f.setUp();self.addCleanup(f.doCleanups)
        self.f=f;a=f.auth;b=a.backend;old=b.prepared.scope;q=old.binding.qa
        qa_keys,qa_private=fixture_keys(a.temp.name,('qa_engineer_service',))
        a.keys.update(qa_keys)
        qa_request=replace(old.request,lease_id='prior-qa',input_digest=q.input_digest)
        qa_output={k:getattr(q,k) for k in q.__dataclass_fields__ if k!='allowed_paths'}
        qa_output.update(kind='factory_review_v1',verdict='ACCEPTED',rationale='Signed QA fixture.',findings=[])
        qa_raw=canonical(qa_output)
        qa_payload={'kind':'role_result','factory_id':q.factory_id,'task_id':q.task_id,
            'binding':a.ledger._binding(qa_request),'dispatch_id':'e'*64,
            'producer_identity':'qa_engineer_service','output_digest':digest(qa_raw),
            'issued_at':int(NOW.timestamp())-7200,'expires_at':int(NOW.timestamp())-6900}
        qa_digest=digest(canonical(qa_payload))
        binding=replace(old.binding,qa_result_digest=qa_digest)
        raw=job_input(binding,json.loads(b.prepared.candidate_files))
        binding=replace(binding,input_digest=digest(raw))
        request=replace(old.request,lease_id='security-cycle',input_digest=digest(raw))
        b.prepared=prepare(binding=binding,request=request,files=json.loads(b.prepared.candidate_files),input_bytes=raw)
        security_lease=replace(a.state.leases[0],lease_id=request.lease_id)
        qa_lease=Lease('prior-qa','qa_engineer','qa_engineer_service',NOW-timedelta(hours=1))
        a.state=replace(a.state,leases=(security_lease,qa_lease),
                        consumed_evidence_ids=frozenset({'result-'+qa_digest[7:]}))
        a.save(a.state)
        a.db.put_item(TableName='security-state',Item=a.states._serialize_lease(a.state,security_lease))
        qa_row={**a.ledger._key(a.state,qa_request),'status':{'S':'RECEIPT_RECORDED'},
            'binding':{'S':a.ledger._binding(qa_request)},
            'dispatch_id':{'S':'e'*64},'receipt_digest':{'S':qa_digest},
            'result_payload':{'S':canonical(qa_payload).decode()},
            'result_signature':{'S':base64.b64encode(sign(qa_payload,qa_private['qa_engineer_service'],a.temp.name)).decode()},
            'result_output':{'S':base64.b64encode(qa_raw).decode()}}
        a.db.put_item(TableName='security-state',Item=qa_row)
        review={'kind':'scope_review','factory_id':q.factory_id,'task_id':q.task_id,
            'binding':a.ledger._binding(request),'reviewer_identity':'product_spec_reviewer_service',
            'verdict':'ACCEPTED','rationale':'Exact security integration fixture.',
            'issued_at':int(NOW.timestamp())-1,'expires_at':int(NOW.timestamp())+600}
        SignedScopeStore('security-state',a.db,a.keys).approve_task(a.state,request,review,
            sign(review,a.private['product_spec_reviewer_service'],a.temp.name),now=NOW)
        a.ledger.enqueue(a.state,request,caller_identity=CONTROLLER_IDENTITY,now=NOW)
        bindings=b.prepared.scope.bindings()
        b.pricing.update(bindings);b.readiness.update(bindings)
        payload={**b.envelope['payload'],**bindings,'pricing_digest':digest(canonical(b.pricing)),
                 'readiness_digest':digest(canonical(b.readiness))}
        b.envelope={'payload':payload,'signature_base64':base64.b64encode(
            sign(payload,a.private['tim_brydges'],a.temp.name)).decode()}
        provenance=ConsumedQAProvenance(binding=binding,qa_binding=q,qa_request=qa_request,
            states=a.states,ledger=a.ledger,historical_key_loader=lambda _:a.keys,clock=lambda:NOW)
        b.verify_prerequisites=provenance
        guard=copy.copy(b);guard.load_credential=None
        test=self
        class Client(NoIO):
            def invoke(self,**kwargs):
                test.invocations+=1
                result=f.runtime.handle(json.loads(kwargs['Payload']))
                return {'StatusCode':200,'ExecutedVersion':'1','Payload':io.BytesIO(json.dumps(result).encode())}
        self.invocations=0
        activation=AutonomyActivation('security-cycle',q.factory_id,q.task_id,q.source_commit,
            q.contract_digest,NOW-timedelta(minutes=1),NOW+timedelta(hours=1))
        self.controller=BoundedSecurityController(activation=activation,deployed_commit=q.source_commit,
            guard=guard,prerequisites=provenance,lambda_api=Client('lambda'),s3=NoIO('s3'),
            function_arn='arn:aws:lambda:ca-central-1:666730517561:function:tims-factory-review-security:1',
            job_versions={'SECURITY_REVIEW':PinnedJobVersion('v1','sha256:'+'f'*64)},enabled=True)
        plan=IntakePlan(q.factory_id,q.task_id,'SECURITY_REVIEW',a.state.version,security_lease,request,{}, {})
        job=ScheduledAutonomyJob(plan,ReceiptVersions('owner-v1','review-v1'),raw,b'contract')
        self.controller.scheduler.jobs.jobs=Mock(load=Mock(return_value=job))
        report={**json.loads(b.prepared.expected_output),'verdict':'ACCEPTED','rationale':'Fixture only.','findings':[]}
        self.response=canonical({'stopReason':'end_turn','output':{'message':{'role':'assistant',
            'content':[{'text':canonical(report).decode()}]}},'usage':{'inputTokens':100,'outputTokens':50,'totalTokens':150}})

    def tick(self):
        return self.controller.tick('tims-software-factory','bounded-review-004')

    def test_exact_cycle_advances_once_then_stops_without_release(self):
        with patch.object(wire.http.client,'HTTPSConnection',return_value=Connection(Response(self.response))) as network:
            result=self.tick()
            self.assertEqual(result['status'],'ADVANCED')
            self.assertEqual(result['progression']['state'],'RELEASE_READY')
            self.assertFalse(result['release_dispatched'])
            again=self.tick()
            self.assertEqual(again['status'],'STOPPED')
        self.assertEqual((self.invocations,network.call_count,self.f.signing.calls),(1,1,1))

    def test_missing_qa_key_stops_before_lambda_or_provider(self):
        self.f.auth.keys.pop('qa_engineer_service')
        with patch.object(wire.http.client,'HTTPSConnection') as network:
            with self.assertRaises(StateError):self.tick()
            network.assert_not_called()
        self.assertEqual(self.invocations,0)

    def test_rejected_security_report_never_advances_or_repeats_provider(self):
        response=json.loads(self.response)
        report=json.loads(response['output']['message']['content'][0]['text'])
        report.update(verdict='REJECTED',findings=[{'severity':'high','path':'fingerprint.py','detail':'Fixture risk.'}])
        response['output']['message']['content'][0]['text']=canonical(report).decode()
        with patch.object(wire.http.client,'HTTPSConnection',return_value=Connection(Response(canonical(response)))) as network:
            for _ in range(2):
                with self.assertRaises(StateError):self.tick()
        state=self.f.auth.states.load_state('tims-software-factory','bounded-review-004')
        self.assertEqual(state.state,'SECURITY_REVIEW')
        self.assertEqual((self.invocations,network.call_count),(1,1))


if __name__ == '__main__':unittest.main()
