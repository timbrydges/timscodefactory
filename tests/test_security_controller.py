from dataclasses import replace
from datetime import timedelta
from types import SimpleNamespace
import unittest
from unittest.mock import Mock

from factory_runtime.acceptance_jobs import PinnedJobVersion
from factory_runtime.autonomy import AutonomyActivation
from factory_runtime.security_controller import BoundedSecurityController
from factory_runtime.security_qa_provenance import ConsumedQAProvenance
from factory_state.model import StateError
import test_security_provider_backend as fixtures
from test_security_provider_claims import NOW, mock_aws
from test_review_controller import NoIO


@unittest.skipIf(mock_aws is None,'Requires moto[dynamodb]')
class SecurityControllerTests(unittest.TestCase):
    def setUp(self):
        fixture=fixtures.SecurityBackendTests();fixture.setUp();self.addCleanup(fixture.doCleanups)
        guard=fixture.backend;guard.load_credential=None;guard.enabled=True
        b=guard.prepared.scope.binding;q=b.qa
        provenance=ConsumedQAProvenance(binding=b,qa_binding=q,
            qa_request=replace(guard.prepared.scope.request,input_digest=q.input_digest),
            states=guard.states,ledger=guard.ledger,historical_key_loader=lambda _: {},clock=lambda:NOW)
        guard.verify_prerequisites=provenance
        self.config=dict(activation=AutonomyActivation('security-test',q.factory_id,q.task_id,
            q.source_commit,q.contract_digest,NOW-timedelta(minutes=1),NOW+timedelta(hours=2)),
            deployed_commit=q.source_commit,guard=guard,prerequisites=provenance,
            lambda_api=NoIO('lambda'),s3=NoIO('s3'),
            function_arn='arn:aws:lambda:ca-central-1:666730517561:function:tims-factory-review-security:1',
            job_versions={'SECURITY_REVIEW':PinnedJobVersion('version-1','sha256:'+'f'*64)})

    def tick(self,service):
        return service.tick(service.activation.factory_id,service.activation.task_id)

    def test_defaults_disabled_and_contains_only_security_executor(self):
        service=BoundedSecurityController(**self.config)
        with self.assertRaisesRegex(StateError,'disabled'):self.tick(service)
        self.assertEqual(set(service.scheduler.cycle.worker.executors),{'deep_security_reviewer'})

    def test_stops_other_stages_without_dispatch(self):
        for stage in ('IMPLEMENTATION','QA','RELEASE_READY','PAUSED'):
            guard=self.config['guard'];guard.states.load_state.return_value=SimpleNamespace(state=stage)
            service=BoundedSecurityController(**self.config,enabled=True)
            service.scheduler=Mock()
            result=self.tick(service)
            self.assertEqual(result['status'],'STOPPED')
            self.assertFalse(result['release_dispatched'])
            service.scheduler.tick.assert_not_called()

    def test_wrong_route_credentials_or_job_stage_rejected(self):
        for change in ({'function_arn':self.config['function_arn'].replace('review-security','qa')},
                       {'job_versions':{}},{'job_versions':{'QA':self.config['job_versions']['SECURITY_REVIEW']}}):
            with self.assertRaises(StateError):BoundedSecurityController(**{**self.config,**change})
        self.config['guard'].load_credential=lambda: 'must never load'
        with self.assertRaises(StateError):BoundedSecurityController(**self.config)

    def test_missing_consumed_qa_stops_before_job_load(self):
        guard=self.config['guard'];q=guard.prepared.scope.binding.qa
        guard.states.load_state.return_value=SimpleNamespace(factory_id=q.factory_id,task_id=q.task_id,
            state='SECURITY_REVIEW',consumed_evidence_ids=frozenset())
        service=BoundedSecurityController(**self.config,enabled=True);service.scheduler=Mock()
        with self.assertRaisesRegex(StateError,'prerequisite'):self.tick(service)
        service.scheduler.tick.assert_not_called()

    def test_expired_test_proof_blocks_guard_and_tick(self):
        guard=self.config['guard'];q=guard.prepared.scope.binding.qa
        service=BoundedSecurityController(**self.config,enabled=True)
        guard.states.load_state.return_value=SimpleNamespace(state='SECURITY_REVIEW')
        guard.evidence.clock=lambda:NOW+timedelta(hours=1,seconds=1)
        service.scheduler.tick=Mock()
        with self.assertRaisesRegex(StateError,'expired'):self.tick(service)
        executor=service.scheduler.cycle.worker.executors['deep_security_reviewer']
        with self.assertRaises(StateError):executor.guard.reserve(None,None,dispatch_id='x',now=NOW)
        service.scheduler.tick.assert_not_called()


if __name__ == '__main__':unittest.main()
