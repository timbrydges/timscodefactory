import asyncio
from dataclasses import replace
from decimal import Decimal
import json
import unittest

from factory_runtime.task_candidate import candidate_workspace
from factory_runtime.task_review import TaskReviewProtocol
from factory_runtime.openai_provider import OpenAIProviderPolicy, OpenAIResponsesProviderInvoker, ProviderHTTPResponse
from factory_state.model import StateError
import test_task_candidate as candidate_fixtures
from test_openai_provider import CountingCredentialSource, StaticPricingSource, RecordingTransport, provider_payload, TARGET


class TaskReviewTests(unittest.TestCase):
    def setUp(self):
        self.fixture = candidate_fixtures.TaskCandidateTests()
        self.fixture.setUp()
        self.candidate = self.enterContext(candidate_workspace(self.fixture.protocol,self.fixture.decision))
        self.request = self.fixture.request(self.candidate)
        self.receipt = self.fixture.receipt(self.request)
        self.args = dict(builder_identity='builder',reviewer_identity='reviewer',now=self.fixture.now)

    def review(self, **changes):
        return TaskReviewProtocol(self.fixture.protocol,self.fixture.decision,self.candidate,
                                  self.request,self.receipt,**{**self.args,**changes})

    def test_packet_contains_exact_changes_and_test_bindings(self):
        review = self.review()
        turn = review.turn
        self.assertEqual(turn['workspace_digest'],self.candidate.workspace_digest)
        self.assertEqual(turn['test_request_digest'],self.request.request_digest)
        self.assertEqual(turn['changes'][0]['before'],'const pageSize = 10;\n')
        self.assertEqual(turn['changes'][0]['after'],'const pageSize = 20;\n')
        turn['changes'][0]['after']='tampered'
        self.assertEqual(review.turn['changes'][0]['after'],'const pageSize = 20;\n')

    def test_same_identity_rejected(self):
        with self.assertRaises(StateError): self.review(reviewer_identity='builder')

    def test_failed_or_timed_out_observation_cannot_enter_review(self):
        for receipt in [replace(self.receipt,exit_code=1),replace(self.receipt,exit_code=None,timed_out=True)]:
            with self.subTest(receipt=receipt),self.assertRaises(StateError):
                TaskReviewProtocol(self.fixture.protocol,self.fixture.decision,self.candidate,
                                   self.request,receipt,**self.args)

    def test_changed_proposal_or_candidate_rejected(self):
        decision={**self.fixture.decision,'summary':'changed'}
        with self.assertRaises(StateError):
            TaskReviewProtocol(self.fixture.protocol,decision,self.candidate,self.request,self.receipt,**self.args)
        (self.candidate.workspace/self.fixture.path).write_bytes(b'tampered')
        with self.assertRaises(StateError): self.review()

    def test_accept_and_reject_remain_non_authoritative(self):
        review = self.review()
        for verdict, findings, status in [('APPROVE',[],'REVIEW_ACCEPTED'),('REJECT',['Missing owner filter'],'REVIEW_REJECTED')]:
            result=review.validate_decision({'review_input_digest':review.input_digest,
                'verdict':verdict,'findings':findings},reviewer_identity='reviewer')
            self.assertEqual(result['status'],status)
            self.assertFalse(result['authoritative'])
            self.assertFalse(result['progression_authorized'])
            self.assertFalse(result['release_authorized'])

    def test_stale_unbound_or_contradictory_review_rejected(self):
        review=self.review()
        decision={'review_input_digest':review.input_digest,'verdict':'APPROVE','findings':[]}
        for change in [{'review_input_digest':'sha256:'+'0'*64},{'verdict':'REJECT'},
                       {'findings':['blocking']},{'release_authorized':True}]:
            with self.subTest(change=change),self.assertRaises(StateError):
                review.validate_decision({**decision,**change},reviewer_identity='reviewer')
        with self.assertRaises(StateError): review.validate_decision(decision,reviewer_identity='builder')

    def test_existing_provider_adapter_transports_review_offline(self):
        review=self.review()
        decision={'review_input_digest':review.input_digest,'verdict':'REJECT','findings':['Fixture requires more evidence']}
        transport=RecordingTransport(ProviderHTTPResponse(200,json.dumps(provider_payload(decision)).encode()))
        invoker=OpenAIResponsesProviderInvoker(CountingCredentialSource(),StaticPricingSource(),transport,
            policy=OpenAIProviderPolicy(live_enabled=True,workload='task_review',max_output_tokens=512))
        result=asyncio.run(invoker.invoke(target=TARGET,turn=review.turn,max_cost_usd=Decimal('1'),decision_schema_version='1'))
        checked=review.validate_decision(result.decision,reviewer_identity='reviewer')
        self.assertEqual(checked['status'],'REVIEW_REJECTED')
        body=json.loads(transport.last_body)
        self.assertEqual(body['text']['format']['schema']['properties']['verdict']['enum'],['APPROVE','REJECT'])
        self.assertIn('Independently review',body['instructions'])
        self.assertEqual(transport.calls,1)


if __name__=='__main__': unittest.main()
