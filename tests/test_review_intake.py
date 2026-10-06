from dataclasses import replace
from datetime import timedelta
import unittest
from unittest.mock import Mock

from factory_runtime.review_intake import prepare_intake
from factory_runtime.review_scope_policy import STAGES, FACTORY, TASK, EVIDENCE, STOP
from factory_state.model import TaskState, CONTROLLER_IDENTITY, StateError
from factory_state.dispatch import DynamoDBDispatchStore
from test_review_material import MaterialTests


class ReviewIntakeTests(unittest.TestCase):
    def setUp(self):
        self.f=MaterialTests();self.f.setUp();self.addCleanup(self.f.doCleanups)
        self.material=self.f.load();self.now=self.f.f.now

    def state(self,role):return TaskState(FACTORY,TASK,STAGES[role],0,self.now,CONTROLLER_IDENTITY)

    def prepare(self,role='builder',states=None,clock=None):
        states=states or Mock(load_state=Mock(return_value=self.state(role)))
        return prepare_intake(material=self.material,role=role,states=states,clock=clock or (lambda:self.now))

    def test_three_current_stages_bind_exact_deployment_requests_without_writes(self):
        for role in STAGES:
            states=Mock(load_state=Mock(return_value=self.state(role)))
            plan=self.prepare(role,states)
            self.assertEqual(plan.request,self.material.prepared(role).scope.request)
            self.assertEqual(plan.lease.lease_id,plan.request.lease_id)
            self.assertEqual(plan.review_payload['binding'],DynamoDBDispatchStore._binding(plan.request))
            self.assertEqual(plan.capability_payload['required_evidence'],EVIDENCE)
            self.assertEqual(plan.capability_payload['stop_condition'],STOP)
            self.assertEqual({c[0] for c in states.mock_calls},{'load_state'})

    def test_missing_wrong_and_changing_stage_fail(self):
        for value in (None,self.state('qa')):
            with self.assertRaises(StateError):self.prepare(states=Mock(load_state=Mock(return_value=value)))
        states=Mock(load_state=Mock(side_effect=[self.state('builder'),replace(self.state('builder'),version=1)]))
        with self.assertRaises(StateError):self.prepare(states=states)

    def test_consumed_lease_is_not_reused_even_after_expiry(self):
        plan=self.prepare()
        old=replace(plan.lease,expires_at=self.now-timedelta(seconds=1))
        states=Mock(load_state=Mock(return_value=replace(self.state('builder'),leases=(old,))))
        with self.assertRaises(StateError):self.prepare(states=states)

    def test_stale_proof_does_not_prepare_future_work(self):
        with self.assertRaises(StateError):self.prepare(clock=lambda:self.now+timedelta(hours=2))
        with self.assertRaises(StateError):self.prepare(role='security',states=Mock())
