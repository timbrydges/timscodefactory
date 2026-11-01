import asyncio
from datetime import datetime, timezone
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from factory_runtime.development_runner import DevelopmentTaskRunner
from factory_runtime.repository_snapshot import RepositoryFile, RepositorySnapshot
from factory_runtime.task_queue import LocalTaskQueue, QueuedTask
from factory_runtime.worker import digest
from factory_runtime.openai_provider import OpenAIProviderProtocolError
from factory_state.model import StateError
from unittest.mock import patch
import test_task_candidate as fixtures


class DevelopmentRunnerTests(unittest.TestCase):
    def setUp(self):
        self.f = fixtures.TaskCandidateTests()
        self.f.setUp()
        self.root = Path(self.enterContext(TemporaryDirectory()))
        self.queue = LocalTaskQueue(self.root / 'queue.db')
        self.task = QueuedTask('entry','factory',self.f.spec['task_id'],'activation',
            'a'*40,digest(self.f.raw),'IMPLEMENTATION')
        self.queue.enqueue(self.task)
        self.queue.pause(False)
        self.calls, self.artifacts = [], []
        self.fail = None
        self.verdict = 'APPROVE'
        self.exit_code = 0
        async def builder(turn):
            self.calls.append('builder')
            if self.fail == 'builder': raise RuntimeError('private detail')
            return self.f.decision
        async def reviewer(turn):
            self.calls.append('reviewer')
            return {'review_input_digest':turn['review_input_digest'], 'verdict':self.verdict,
                    'findings':[] if self.verdict == 'APPROVE' else ['Missing requirement']}
        outer = self
        class Sandbox:
            async def execute(self, request):
                outer.calls.append('tests')
                return outer.f.receipt(request, exit_code=outer.exit_code)
        def save(entry, raw):
            if self.fail == 'save': raise OSError('disk failure')
            self.artifacts.append(json.loads(raw))
        snapshot = RepositorySnapshot(self.f.spec['repository'],self.f.spec['target_commit'],
            (RepositoryFile(self.f.path,self.f.files[self.f.path].encode(),False),))
        self.runner = DevelopmentTaskRunner(self.queue, contract_bytes=self.f.raw, snapshot=snapshot,
            builder=builder, reviewer=reviewer, request_for=self.f.request,
            sandbox_for=lambda candidate: Sandbox(),save_artifact=save,
            clock=lambda:datetime.now(timezone.utc),builder_identity='builder',reviewer_identity='reviewer')

    def tick(self): return asyncio.run(self.runner.tick())

    def test_disabled_and_paused_do_no_work(self):
        self.assertEqual(self.tick()['status'],'DISABLED')
        self.runner.enabled=True
        self.queue.pause(True)
        self.assertEqual(self.tick()['status'],'IDLE_OR_PAUSED')
        self.assertEqual(self.calls,[])

    def test_connected_success_persists_bound_artifact_and_never_repeats(self):
        self.runner.enabled=True
        result=self.tick()
        self.assertEqual(result['status'],'TICK_COMPLETED')
        self.assertEqual(self.calls,['builder','tests','reviewer'])
        self.assertFalse(self.artifacts[0]['release_authorized'])
        self.assertEqual(self.artifacts[0]['review_packet']['test_request_digest'],
                         self.artifacts[0]['test_observation']['request_digest'])
        self.queue.enqueue(self.task)
        self.assertEqual(self.tick()['status'],'IDLE_OR_PAUSED')
        self.assertEqual(len(self.calls),3)

    def test_failed_tests_stop_before_review_and_retain_evidence(self):
        self.runner.enabled=True
        self.exit_code=1
        self.assertEqual(self.tick()['status'],'REJECTED')
        self.assertEqual(self.calls,['builder','tests'])
        self.assertEqual(self.artifacts[0]['result']['status'],'TESTS_FAILED')

    def test_rejected_review_is_not_success(self):
        self.runner.enabled=True
        self.verdict='REJECT'
        self.assertEqual(self.tick()['status'],'REJECTED')
        self.assertEqual(self.artifacts[0]['result']['status'],'REVIEW_REJECTED')

    def test_external_and_artifact_failures_are_consumed_without_secret_details(self):
        for phase in ['builder','save']:
            with self.subTest(phase=phase):
                self.setUp()
                self.runner.enabled=True
                self.fail=phase
                result=self.tick()
                self.assertEqual(result['status'],'NEEDS_RECONCILIATION')
                self.assertNotIn('private detail',json.dumps(result))
                self.assertEqual(self.tick()['status'],'IDLE_OR_PAUSED')

    def test_binding_failure_before_builder(self):
        self.runner.enabled=True
        self.runner.contract_bytes=b'{}'
        self.assertEqual(self.tick()['status'],'NEEDS_RECONCILIATION')
        self.assertEqual(self.calls,[])

    def test_provider_failure_reason_is_safe_durable_and_never_retried(self):
        self.runner.enabled = True
        async def fail(turn):
            self.calls.append('builder')
            raise OpenAIProviderProtocolError('private-provider-body', failure_code='timeout')
        self.runner.builder = fail
        result = self.tick()
        self.assertEqual(result['result']['failure_code'], 'timeout')
        self.assertEqual(result['result']['phase'], 'BUILDER')
        self.assertNotIn('private-provider-body', json.dumps(result))
        self.assertEqual(self.tick()['status'], 'IDLE_OR_PAUSED')
        self.assertEqual(self.calls, ['builder'])

    def test_failure_code_cannot_carry_untrusted_text(self):
        self.runner.enabled = True
        async def fail(turn):
            error = OpenAIProviderProtocolError('private', failure_code='timeout')
            error.failure_code = 'private credential'
            raise error
        self.runner.builder = fail
        result = self.tick()
        self.assertEqual(result['result']['failure_code'], 'protocol_failure')
        self.assertNotIn('private', json.dumps(result))

    def test_unknown_task_validation_message_is_not_persisted(self):
        self.runner.enabled = True
        with patch('factory_runtime.development_runner.TaskImplementationProtocol.validate_decision',
                   side_effect=StateError('private validation detail')):
            result = self.tick()
        self.assertEqual(result['result']['failure_code'], 'task_validation_failure')
        self.assertNotIn('private validation detail', json.dumps(result))
        self.assertEqual(self.calls, ['builder'])
        self.assertEqual(self.tick()['status'], 'IDLE_OR_PAUSED')

    def test_one_shot_partial_proposal_stops_before_sandbox_or_review(self):
        import test_task_new_files
        f = test_task_new_files.TaskNewFileTests()
        f.setUp()
        self.runner.snapshot = f.snapshot
        self.runner.delivery = {'mode': 'complete_task_single_proposal',
            'required_changed_paths': [f.page, f.helper, f.test],
            'test_command': ['node', '--test', f.test]}
        # Reproduce the live v5 shape: helper only, no dashboard or tests.
        self.f.decision = {**f.decision, 'edits': [f.decision['edits'][0]]}
        self.runner.enabled = True
        result = self.tick()
        self.assertEqual(result['result']['failure_code'], 'incomplete_delivery')
        self.assertEqual(result['result']['phase'], 'PROPOSAL_VALIDATION')
        self.assertEqual(self.calls, ['builder'])
        self.assertEqual(self.tick()['status'], 'IDLE_OR_PAUSED')

    def test_one_shot_complete_proposal_reaches_tests_and_review_offline(self):
        import test_task_new_files
        f = test_task_new_files.TaskNewFileTests()
        f.setUp()
        self.runner.snapshot = f.snapshot
        self.f.decision = f.decision
        self.runner.delivery = {'mode': 'complete_task_single_proposal',
            'required_changed_paths': [f.page, f.helper, f.test],
            'test_command': ['node', '--test']}
        self.runner.enabled = True
        result = self.tick()
        self.assertEqual(result['status'], 'TICK_COMPLETED')
        self.assertEqual(self.calls, ['builder', 'tests', 'reviewer'])
        self.assertFalse(self.artifacts[0]['release_authorized'])

    def test_one_shot_command_drift_stops_before_execution(self):
        self.runner.delivery = {'mode': 'complete_task_single_proposal',
            'required_changed_paths': [self.f.path], 'test_command': ['different-command']}
        self.runner.enabled = True
        result = self.tick()
        self.assertEqual(result['result']['phase'], 'CANDIDATE')
        self.assertEqual(self.calls, ['builder'])
        self.assertEqual(self.tick()['status'], 'IDLE_OR_PAUSED')


class DevelopmentRepairRoundTests(DevelopmentRunnerTests):
    def setUp(self):
        super().setUp()
        self.verdicts = ['REJECT', 'APPROVE']
        self.repair_turns, self.repair_evidence = [], []
        async def reviewer(turn):
            self.calls.append('reviewer')
            verdict = self.verdicts.pop(0)
            return {'review_input_digest': turn['review_input_digest'], 'verdict': verdict,
                    'findings': [] if verdict == 'APPROVE' else ['Type of readLibraryPage is not inferred']}
        async def repair_builder(turn):
            self.calls.append('repair_builder'); self.repair_turns.append(turn)
            if self.fail == 'repair': raise RuntimeError('private detail')
            return self.repair_decision
        self.repair_decision = self.f.decision
        r = self.runner
        self.runner = DevelopmentTaskRunner(self.queue, contract_bytes=r.contract_bytes,
            snapshot=r.snapshot, builder=r.builder, reviewer=reviewer, request_for=r.request_for,
            sandbox_for=r.sandbox_for, save_artifact=r.save_artifact, clock=r.clock,
            builder_identity='builder', reviewer_identity='reviewer', enabled=True,
            repair_rounds=1, repair_builder=repair_builder, repair_reviewer=reviewer,
            save_repair_test_evidence=lambda entry, raw: self.repair_evidence.append(json.loads(raw)))

    def test_rejection_gets_exactly_one_repair_and_rereview(self):
        result = self.tick()
        self.assertEqual(result['status'], 'TICK_COMPLETED')
        self.assertEqual(self.calls, ['builder', 'tests', 'reviewer', 'repair_builder', 'tests', 'reviewer'])
        repair = self.repair_turns[0]['repair']
        self.assertEqual(repair['review_findings'], ['Type of readLibraryPage is not inferred'])
        self.assertEqual(repair['rejected_decision_digest'], digest(
            json.dumps(self.f.decision, sort_keys=True, separators=(',', ':')).encode()))
        artifact = self.artifacts[0]
        self.assertEqual(artifact['repair_round'], 1)
        self.assertEqual(artifact['first_round']['review_decision']['verdict'], 'REJECT')
        self.assertEqual(artifact['review_decision']['verdict'], 'APPROVE')
        self.assertEqual(len(self.repair_evidence), 1)
        self.assertFalse(artifact['release_authorized'])

    def test_second_rejection_stops_without_another_repair(self):
        self.verdicts = ['REJECT', 'REJECT']
        self.assertEqual(self.tick()['status'], 'REJECTED')
        self.assertEqual(self.calls.count('repair_builder'), 1)
        self.assertEqual(self.calls.count('reviewer'), 2)

    def test_repair_failure_is_uncertain_and_never_retried(self):
        self.fail = 'repair'
        result = self.tick()
        self.assertEqual((result['status'], result['result']['phase']),
                         ('NEEDS_RECONCILIATION', 'REPAIR_BUILDER'))
        self.assertEqual(self.calls.count('repair_builder'), 1)
        self.assertEqual(self.artifacts, [])

    def test_repair_escalation_stops_with_first_round_retained(self):
        self.repair_decision = {'type': 'escalate', 'reason': 'Needs a schema change'}
        result = self.tick()
        self.assertEqual(result['status'], 'STOPPED')
        self.assertEqual(result['result']['status'], 'REPAIR_NEEDS_INPUT')
        self.assertEqual(self.artifacts[0]['repair']['first_round']['review_decision']['verdict'], 'REJECT')

    def test_without_approved_repair_rejection_is_final(self):
        self.runner.repair_rounds = 0
        self.verdicts = ['REJECT']
        self.assertEqual(self.tick()['status'], 'REJECTED')
        self.assertNotIn('repair_builder', self.calls)

    def test_invalid_repair_configuration_rejected(self):
        for kw in ({'repair_rounds': 3}, {'repair_rounds': 1, 'repair_builder': None}, {'repair_rounds': True}):
            with self.subTest(kw=kw), self.assertRaises(StateError):
                DevelopmentTaskRunner(self.queue, contract_bytes=self.f.raw, snapshot=self.runner.snapshot,
                    builder=self.runner.builder, reviewer=self.runner.reviewer,
                    request_for=self.f.request, sandbox_for=self.runner.sandbox_for,
                    save_artifact=self.runner.save_artifact, clock=self.runner.clock,
                    builder_identity='builder', reviewer_identity='reviewer',
                    **{'repair_builder': self.runner.repair_builder,
                       'repair_reviewer': self.runner.repair_reviewer, **kw})



# Inherited single-round tests do not apply to the repair fixture.
for _name in dir(DevelopmentRunnerTests):
    if _name.startswith('test_') and _name not in DevelopmentRepairRoundTests.__dict__:
        setattr(DevelopmentRepairRoundTests, _name, None)


class FailedChecksRepairTests(unittest.TestCase):
    def setUp(self):
        base = DevelopmentRepairRoundTests('test_rejection_gets_exactly_one_repair_and_rereview')
        base.setUp(); self.addCleanup(base.doCleanups)
        self.base = base
        self.exit_codes = [1, 0]
        outer = self
        class Sandbox:
            async def execute(self, request):
                base.calls.append('tests')
                return base.f.receipt(request, exit_code=outer.exit_codes.pop(0))
        class Diagnostics:
            def __init__(self): self.taken = []
            def take(self, request, receipt):
                self.taken.append(receipt.exit_code)
                from types import SimpleNamespace
                return SimpleNamespace(stdout_excerpt='page.tsx 39:15 error Unexpected any', stderr_excerpt='')
        self.diagnostics = Diagnostics()
        base.verdicts = ['APPROVE']
        r = base.runner
        r.sandbox_for = lambda candidate: Sandbox()
        r.diagnostics = self.diagnostics

    def test_failed_checks_feed_one_repair_then_review(self):
        result = self.base.tick()
        self.assertEqual(result['status'], 'TICK_COMPLETED')
        self.assertEqual(self.base.calls, ['builder', 'tests', 'repair_builder', 'tests', 'reviewer'])
        finding = self.base.repair_turns[0]['repair']['review_findings'][0]
        self.assertIn('TESTS_FAILED, exit code 1', finding)
        self.assertIn('Unexpected any', finding)
        self.assertEqual(self.base.artifacts[0]['first_round']['result']['status'], 'TESTS_FAILED')

    def test_checks_failing_again_stop_without_second_repair(self):
        self.exit_codes = [1, 1]
        self.assertEqual(self.base.tick()['status'], 'REJECTED')
        self.assertEqual(self.base.calls.count('repair_builder'), 1)
        self.assertNotIn('reviewer', self.base.calls)

    def test_without_output_no_repair_is_attempted(self):
        self.base.runner.diagnostics = None
        self.assertEqual(self.base.tick()['status'], 'REJECTED')
        self.assertNotIn('repair_builder', self.base.calls)


class AcceptanceTestInjectionTests(unittest.TestCase):
    def setUp(self):
        base = DevelopmentRunnerTests('test_disabled_and_paused_do_no_work')
        base.setUp(); self.addCleanup(base.doCleanups)
        self.base = base
        self.seen = {}
        outer = self
        class Sandbox:
            async def execute(self, request):
                outer.seen = {p.relative_to(self.workspace).as_posix(): p.read_text()
                              for p in self.workspace.rglob('*') if p.is_file()}
                return base.f.receipt(request, exit_code=0)
        def sandbox_for(candidate):
            sandbox = Sandbox(); sandbox.workspace = candidate.workspace; return sandbox
        base.runner.sandbox_for = sandbox_for
        base.runner.enabled = True

    def test_contract_acceptance_tests_are_in_the_tested_workspace(self):
        spec = json.loads(self.base.f.raw)
        self.assertEqual(self.base.tick()['status'], 'TICK_COMPLETED')
        test = spec['acceptance_tests'][0]
        self.assertEqual(self.seen[test['path']], test['content'])
        self.assertNotIn(test['path'], spec['allowed_paths'])

    def test_acceptance_paths_must_be_new_and_contract_owned(self):
        spec = json.loads(self.base.f.raw)
        for item in ({'path': 'src/app/dashboard/page.tsx', 'content': 'x'},
                     {'path': 'tests/factory-acceptance/../x.test.mjs', 'content': 'x'},
                     {'path': 'tests/other.test.mjs', 'content': 'x'},
                     {'path': 'tests/factory-acceptance/a.test.mjs', 'content': ''},
                     {'path': 'tests/factory-acceptance/a.test.mjs', 'content': 'x', 'extra': 1}):
            with self.subTest(item=item), self.assertRaises(StateError):
                self.base.runner._with_acceptance_tests({**spec, 'acceptance_tests': [item]})

    def test_task_contract_embeds_the_reviewed_acceptance_file(self):
        root = Path(__file__).resolve().parents[1]
        spec = json.loads(self.base.f.raw)
        source = (root/'factory/projects/bonus-library-pagination/acceptance/library-pagination.acceptance.test.mjs').read_text()
        self.assertEqual(spec['acceptance_tests'][0]['content'], source)
        from factory_runtime.development_composition import BONUS_REPOSITORY_CHECKS
        self.assertIn(spec['acceptance_tests'][0]['path'], BONUS_REPOSITORY_CHECKS[2])


class TwoRepairRoundsTests(unittest.TestCase):
    def setUp(self):
        base = DevelopmentRepairRoundTests('test_rejection_gets_exactly_one_repair_and_rereview')
        base.setUp(); self.addCleanup(base.doCleanups)
        self.base = base
        self.rounds_seen, self.evidence_rounds = [], []
        async def reviewer(turn, round=1):
            base.calls.append('reviewer'); self.rounds_seen.append(round)
            verdict = base.verdicts.pop(0)
            return {'review_input_digest': turn['review_input_digest'], 'verdict': verdict,
                    'findings': [] if verdict == 'APPROVE' else [f'Defect {len(base.verdicts)}']}
        r = base.runner
        r.reviewer, r.repair_reviewer, r.repair_rounds = reviewer, reviewer, 2
        r.save_repair_test_evidence = lambda entry, raw, round=1: self.evidence_rounds.append(round)

    def test_second_repair_follows_a_second_rejection_then_approval(self):
        self.base.verdicts = ['REJECT', 'REJECT', 'APPROVE']
        self.assertEqual(self.base.tick()['status'], 'TICK_COMPLETED')
        self.assertEqual(self.base.calls, ['builder', 'tests', 'reviewer', 'repair_builder', 'tests',
                                           'reviewer', 'repair_builder', 'tests', 'reviewer'])
        turns = self.base.repair_turns
        self.assertEqual([t['repair']['round'] for t in turns], [1, 2])
        self.assertIn('repair 2 of 2', turns[1]['repair']['instruction'])
        self.assertEqual(self.rounds_seen, [1, 1, 2])
        self.assertEqual(self.evidence_rounds, [1, 2])
        artifact = self.base.artifacts[0]
        self.assertEqual(artifact['repair_round'], 2)
        self.assertEqual(len(artifact['previous_rounds']), 2)

    def test_no_third_repair(self):
        self.base.verdicts = ['REJECT', 'REJECT', 'REJECT']
        self.assertEqual(self.base.tick()['status'], 'REJECTED')
        self.assertEqual(self.base.calls.count('repair_builder'), 2)

    def test_approval_after_first_repair_skips_second(self):
        self.base.verdicts = ['REJECT', 'APPROVE']
        self.assertEqual(self.base.tick()['status'], 'TICK_COMPLETED')
        self.assertEqual(self.base.calls.count('repair_builder'), 1)
