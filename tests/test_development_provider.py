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
                    decision = {'decision': outer.f.f.decision}
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

    def test_rejected_task_proposal_is_retained_before_validation_without_authority(self):
        self.session.enabled = self.f.runner.enabled = True
        self.f.f.decision['edits'][0]['old_text'] = 'not present in pinned source'
        result = self.f.tick()
        self.assertEqual(result['result']['phase'], 'PROPOSAL_VALIDATION')
        self.assertEqual(result['result']['failure_code'], 'source_match_not_unique')
        evidence = self.events['builder.completed']
        self.assertEqual(evidence['proposal'], self.f.f.decision)
        self.assertFalse(evidence['authoritative'])
        from factory_state.scope import canonical
        from factory_runtime.worker import digest
        self.assertEqual(evidence['decision_digest'], digest(canonical(evidence['proposal'])))
        self.assertNotIn('provider-test-secret', json.dumps(evidence))
        self.assertEqual(self.f.calls, [])  # Neither sandbox nor reviewer reached.
        self.assertEqual(self.f.tick()['status'], 'IDLE_OR_PAUSED')
        self.assertEqual(len(self.requests), 1)

    def test_oversize_proposal_retains_hash_and_usage_but_not_content(self):
        self.session.enabled = self.f.runner.enabled = True
        self.f.f.decision['summary'] = 'x' * 33000
        result = self.f.tick()
        self.assertEqual(result['result']['failure_code'], 'proposal_byte_limit')
        evidence = self.events['builder.completed']
        self.assertIsNone(evidence['proposal'])
        self.assertGreater(evidence['proposal_bytes'], 32000)
        self.assertEqual(evidence['input_tokens'], 1000)
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


class DevelopmentRepairSessionTests(unittest.TestCase):
    def setUp(self):
        base = DevelopmentProviderTests('test_disabled_session_has_no_provider_io')
        base.setUp(); self.addCleanup(base.doCleanups)
        self.base = base
        self.verdicts = ['REJECT', 'APPROVE']
        outer = self
        class Transport:
            async def post_json(self, *, endpoint, headers, body, timeout_seconds):
                turn = json.loads(json.loads(body)['input'])
                base.requests.append(turn)
                if turn['kind'] == 'factory_task_implementation_v1':
                    decision = {'decision': base.f.f.decision}
                else:
                    verdict = outer.verdicts.pop(0)
                    decision = {'review_input_digest': turn['review_input_digest'], 'verdict': verdict,
                                'findings': [] if verdict == 'APPROVE' else ['Generic type is not inferred']}
                return ProviderHTTPResponse(200, json.dumps(provider_fixtures.provider_payload(decision)).encode())
        def adapter(workload):
            return OpenAIResponsesProviderInvoker(provider_fixtures.CountingCredentialSource(),
                provider_fixtures.StaticPricingSource(), Transport(),
                policy=OpenAIProviderPolicy(live_enabled=True, workload=workload))
        def journal(name, evidence):
            if name in base.events: raise FileExistsError('consumed stage')
            base.events[name] = evidence
        self.session = DevelopmentProviderSession(builder=adapter('task_implementation'),
            reviewer=adapter('task_review'), target=provider_fixtures.TARGET,
            builder_cap=Decimal('1'), reviewer_cap=Decimal('1'), total_cap=Decimal('4'),
            journal=journal, enabled=True, repair_rounds=1)
        r = base.f.runner
        r.builder, r.reviewer = self.session.build, self.session.review
        r.repair_rounds, r.repair_builder, r.repair_reviewer = 1, self.session.repair_build, self.session.repair_review
        r.save_repair_test_evidence = None
        r.enabled = True

    def test_repair_round_journals_each_stage_once_with_bound_digests(self):
        self.assertEqual(self.base.f.tick()['status'], 'TICK_COMPLETED')
        self.assertEqual([e for e in self.base.events if e.endswith('.started')],
            ['builder.started', 'reviewer.started', 'repair_builder.started', 'repair_reviewer.started'])
        repair_turn = self.base.requests[2]
        self.assertEqual(repair_turn['repair']['review_findings'], ['Generic type is not inferred'])
        self.assertEqual(repair_turn['repair']['rejected_decision_digest'],
                         self.base.events['builder.completed']['decision_digest'])

    def test_repair_requires_approved_round_and_total_budget(self):
        kw = dict(builder=self.session.adapters['builder'], reviewer=self.session.adapters['reviewer'],
                  target=provider_fixtures.TARGET, builder_cap=Decimal('1'), reviewer_cap=Decimal('1'),
                  journal=lambda *a: None, enabled=True)
        with self.assertRaises(StateError):
            DevelopmentProviderSession(total_cap=Decimal('3.99'), repair_rounds=1, **kw)
        with self.assertRaises(StateError):
            DevelopmentProviderSession(total_cap=Decimal('9'), repair_rounds=2, **kw)
        single = DevelopmentProviderSession(total_cap=Decimal('2'), **kw)
        with self.assertRaises(StateError):
            asyncio.run(single.repair_build({'kind': 'factory_task_implementation_v1', 'repair': {}}))

    def test_repair_cannot_run_before_review_or_with_unbound_rejection(self):
        with self.assertRaises(StateError):
            asyncio.run(self.session.repair_build({'kind': 'factory_task_implementation_v1',
                                                  'repair': {'rejected_decision_digest': 'x'}}))
        self.assertEqual(self.base.events, {})
