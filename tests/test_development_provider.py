"""Real runner and Responses serialization, with no network or real credentials."""
import asyncio
import json
from decimal import Decimal
import unittest
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))

from factory_runtime.development_provider import DevelopmentProviderSession, ExclusiveDevelopmentJournal
from factory_runtime.openai_provider import (
    OpenAIResponsesProviderInvoker, OpenAIProviderPolicy, ProviderHTTPResponse)
from factory_state.model import StateError
import test_development_runner as runner_fixtures
import test_openai_provider as provider_fixtures


class DevelopmentProviderTests(unittest.TestCase):
    def setUp(self):
        self.f = runner_fixtures.DevelopmentRunnerTests()
        self.f.setUp()
        self.addCleanup(self.f.doCleanups)
        self.events, self.requests = {}, []
        self.fail_transport = False
        self.incomplete = False
        outer = self
        class Transport:
            async def post_json(self, *, endpoint, headers, body, timeout_seconds):
                request = json.loads(body)
                turn = json.loads(request['input'])
                outer.requests.append(request)
                if outer.fail_transport:
                    raise TimeoutError('private token must not escape')
                if turn['kind'] == 'factory_task_implementation_v1':
                    decision = {**outer.f.f.decision, 'paths': [], 'reason': ''}
                else:
                    decision = {'review_input_digest': turn['review_input_digest'],
                                'verdict': 'APPROVE', 'findings': []}
                payload = provider_fixtures.provider_payload(decision)
                if outer.incomplete:
                    payload.update(status='incomplete', incomplete_details={'reason': 'max_output_tokens'},
                                   output=[{'private': 'must not persist'}])
                return ProviderHTTPResponse(200, json.dumps(payload).encode())
        def adapter(workload):
            return OpenAIResponsesProviderInvoker(provider_fixtures.CountingCredentialSource(),
                provider_fixtures.StaticPricingSource(), Transport(),
                policy=OpenAIProviderPolicy(live_enabled=True, workload=workload))
        self.builder, self.reviewer = adapter('task_implementation'), adapter('task_review')
        def journal(name, evidence):
            if name in self.events:
                raise FileExistsError('consumed stage')
            self.events[name] = evidence
        self.session = DevelopmentProviderSession(builder=self.builder, reviewer=self.reviewer,
            target=provider_fixtures.TARGET, builder_cap=Decimal('1'), reviewer_cap=Decimal('1'),
            total_cap=Decimal('2'), journal=journal)
        self.f.runner.builder, self.f.runner.reviewer = self.session.build, self.session.review

    def test_disabled_session_has_no_provider_io(self):
        self.f.runner.enabled = True
        self.assertEqual(self.f.tick()['status'], 'NEEDS_RECONCILIATION')
        self.assertEqual(self.requests, [])
        self.assertEqual(self.events, {})

    def test_runner_connects_both_adapter_workloads_and_retains_cost_evidence(self):
        self.session.enabled = self.f.runner.enabled = True
        self.assertEqual(self.f.tick()['status'], 'TICK_COMPLETED')
        self.assertEqual(list(self.events), ['builder.started', 'builder.completed',
                                            'reviewer.started', 'reviewer.completed'])
        self.assertEqual(len(self.requests), 2)
        for request in self.requests:
            self.assertIs(request['store'], False)
            self.assertNotIn('tools', request)
        self.assertNotIn('provider-test-secret', json.dumps(self.events))
        self.assertEqual(self.events['builder.completed']['input_tokens'], 1000)
        self.assertEqual(self.f.tick()['status'], 'IDLE_OR_PAUSED')
        self.assertEqual(len(self.requests), 2)

    def test_uncertain_provider_result_consumes_call_and_stops_review(self):
        self.session.enabled = self.f.runner.enabled = True
        self.fail_transport = True
        result = self.f.tick()
        self.assertEqual(result['status'], 'NEEDS_RECONCILIATION')
        self.assertEqual(list(self.events), ['builder.started', 'builder.failed'])
        self.assertEqual(self.events['builder.failed']['failure_code'], 'timeout')
        self.assertEqual(self.events['builder.failed']['response_evidence'], {})
        self.assertNotIn('private token', json.dumps(self.events))
        self.assertNotIn('private token', json.dumps(result))
        with self.assertRaises(StateError):
            asyncio.run(self.session.build({'kind': 'factory_task_implementation_v1'}))
        self.assertEqual(len(self.requests), 1)

    def test_incomplete_response_retains_usage_without_content_and_cannot_repeat(self):
        self.session.enabled = self.f.runner.enabled = True
        self.incomplete = True
        self.session.journal = ExclusiveDevelopmentJournal(self.f.root)
        result = self.f.tick()
        self.assertEqual(result['result']['failure_code'], 'output_token_limit')
        evidence = json.loads((self.f.root / 'builder.failed.json').read_text())
        self.assertEqual(evidence['response_evidence']['output_tokens'], 100)
        self.assertEqual(evidence['response_evidence']['incomplete_reason'], 'max_output_tokens')
        self.assertFalse(evidence['billing_reconciled'])
        self.assertNotIn('must not persist', json.dumps(evidence))
        self.assertEqual(self.session.completed, set())
        self.assertEqual(self.f.tick()['status'], 'IDLE_OR_PAUSED')
        self.assertEqual(len(self.requests), 1)

    def test_persisted_start_prevents_recreated_session_from_dispatching(self):
        journal = ExclusiveDevelopmentJournal(self.f.root)
        journal('builder.started', {'stage': 'builder'})
        self.session.journal = ExclusiveDevelopmentJournal(self.f.root)
        self.session.enabled = self.f.runner.enabled = True
        self.assertEqual(self.f.tick()['status'], 'NEEDS_RECONCILIATION')
        self.assertEqual(self.requests, [])

    def test_journal_failure_after_response_stops_before_review(self):
        self.session.enabled = self.f.runner.enabled = True
        def journal(event, evidence):
            if event == 'builder.completed':
                raise OSError('disk full')
        self.session.journal = journal
        self.assertEqual(self.f.tick()['status'], 'NEEDS_RECONCILIATION')
        self.assertEqual(len(self.requests), 1)
        self.assertEqual(self.session.completed, set())

    def test_review_from_another_candidate_stops_before_provider(self):
        self.session.enabled = self.f.runner.enabled = True
        self.assertEqual(self.f.tick()['status'], 'TICK_COMPLETED')
        self.session.started.remove('reviewer')
        with self.assertRaises(StateError):
            asyncio.run(self.session.review({'kind': 'factory_task_review_v1',
                                             'candidate_input_digest': 'wrong'}))
        self.assertEqual(len(self.requests), 2)

    def test_stage_caps_cannot_exceed_total(self):
        with self.assertRaises(StateError):
            DevelopmentProviderSession(builder=self.builder, reviewer=self.reviewer,
                target=provider_fixtures.TARGET, builder_cap=Decimal('1'),
                reviewer_cap=Decimal('1'), total_cap=Decimal('1'), journal=lambda *a: None)
