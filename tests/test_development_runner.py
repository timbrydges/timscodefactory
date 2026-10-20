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
