import asyncio
from dataclasses import replace
from decimal import Decimal
import json
from pathlib import Path
from datetime import datetime, timezone
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from factory_runtime.task_provider import TaskImplementationProtocol
from factory_runtime.task_queue import QueuedTask, LocalTaskQueue, GenericTaskRunner
from factory_runtime.task_admission import AuthenticatedTaskAdmission, plan_binding
from factory_runtime.worker import digest
from factory_runtime.openai_provider import OpenAIProviderPolicy, OpenAIResponsesProviderInvoker, ProviderHTTPResponse
from factory_state.model import StateError
from test_openai_provider import (CountingCredentialSource, StaticPricingSource, RecordingTransport,
                                  provider_payload, TARGET)
from test_task_admission import FixtureVerifier


class TaskProviderTests(unittest.TestCase):
    def setUp(self):
        self.raw=(Path(__file__).resolve().parents[1]/'factory/projects/bonus-library-pagination/task.json').read_bytes()
        self.spec=json.loads(self.raw)
        self.task=QueuedTask('entry','factory',self.spec['task_id'],'activation','a'*40,digest(self.raw),'IMPLEMENTATION')
        # Synthetic source context, not proof of implemented pagination.
        self.files={'src/app/dashboard/page.tsx':'const pageSize = 10;\n'}
        self.args=dict(repository=self.spec['repository'],target_commit=self.spec['target_commit'],contract_bytes=self.raw,files=self.files)
        self.protocol=TaskImplementationProtocol(self.task,**self.args)

    def test_existing_openai_adapter_prepares_bounded_task_request_offline(self):
        decision={'type':'apply_edits','summary':'Proposed page size extraction',
            'edits':[{'path':'src/app/dashboard/page.tsx','old_text':'10','new_text':'PAGE_SIZE'}]}
        transport=RecordingTransport(ProviderHTTPResponse(200,json.dumps(provider_payload({'decision':decision})).encode()))
        invoker=OpenAIResponsesProviderInvoker(CountingCredentialSource(),StaticPricingSource(),transport,
            policy=OpenAIProviderPolicy(live_enabled=True,workload='task_implementation',max_output_tokens=512))
        with patch('socket.create_connection',side_effect=AssertionError('network forbidden')):
            result=asyncio.run(invoker.invoke(target=TARGET,turn=self.protocol.turn,
                max_cost_usd=Decimal('1'),decision_schema_version='1'))
        checked=self.protocol.validate_decision(result.decision)
        self.assertEqual(checked['status'],'PROPOSAL_ONLY')
        self.assertFalse(checked['changes_applied'])
        body=json.loads(transport.last_body)
        self.assertFalse(body['store'])
        self.assertNotIn('tools',body)
        self.assertIn('bounded implementation',body['instructions'])
        self.assertEqual(json.loads(body['input'])['contract_digest'],self.task.contract_digest)
        self.assertEqual(transport.calls,1)
        self.assertEqual(self.files['src/app/dashboard/page.tsx'],'const pageSize = 10;\n')

    def test_changed_pins_and_out_of_scope_source_are_rejected(self):
        for changes in [dict(target_commit='b'*40),dict(repository='other/repo'),
                        dict(contract_bytes=self.raw+b' '),dict(files={'.env':'secret'})]:
            with self.subTest(changes=changes),self.assertRaises(StateError):
                TaskImplementationProtocol(self.task,**{**self.args,**changes})

    def test_wrong_role_cannot_propose_implementation(self):
        with self.assertRaises(StateError):
            TaskImplementationProtocol(replace(self.task,expected_state='QA'),**self.args)

    def test_out_of_scope_and_stale_edits_fail_closed(self):
        for path,old in [('../secret','10'),('src/app/dashboard/page.tsx','missing'),('tests/library-pagination.test.mjs','10')]:
            with self.subTest(path=path,old=old),self.assertRaises(StateError):
                self.protocol.validate_decision({'type':'apply_edits','summary':'x',
                    'edits':[{'path':path,'old_text':old,'new_text':'x'}]})
        with self.assertRaises(StateError):
            self.protocol.validate_decision({'type':'read_files','paths':['.env']})

    def test_escalation_and_input_snapshot_do_not_grant_authority(self):
        before=self.protocol.input_digest
        turn=self.protocol.turn;turn['repository']='attacker/repo'
        self.assertEqual(self.protocol.input_digest,before)
        result=self.protocol.validate_decision({'type':'escalate','reason':'Need more context'})
        self.assertEqual(result['status'],'ESCALATED')
        self.assertFalse(result['tests_executed'])

    def test_authenticated_queue_to_offline_provider_stops_at_proposal(self):
        now=datetime.now(timezone.utc)
        tasks=[replace(self.task,entry_id=f'entry-{i}',expected_state=state)
               for i,state in enumerate(['IMPLEMENTATION','INSPECTION','QA'])]
        args=dict(plan_id='plan',repository=self.spec['repository'],target_commit=self.spec['target_commit'],
                  contract_bytes=self.raw,tasks=tasks)
        from factory_state.model import OWNER_IDENTITY
        payload={'kind':'factory_queue_admission_v1','owner':OWNER_IDENTITY,'receipt_id':'offline-receipt',
            'issued_at':int(now.timestamp()),'expires_at':int(now.timestamp())+3600,'plan':plan_binding(**args),
            'execution_authorized':False,'spending_authorized':False,'signing_authorized':False,'release_authorized':False}
        decision={'type':'read_files','paths':['src/app/dashboard/page.tsx']}
        transport=RecordingTransport(ProviderHTTPResponse(200,json.dumps(provider_payload({'decision':decision})).encode()))
        credentials=CountingCredentialSource()
        invoker=OpenAIResponsesProviderInvoker(credentials,StaticPricingSource(),transport,
            policy=OpenAIProviderPolicy(live_enabled=True,workload='task_implementation',max_output_tokens=512))
        def scheduler(task):
            def tick(*args,expected_state=None):
                self.assertEqual(expected_state,'IMPLEMENTATION')
                packet=TaskImplementationProtocol(task,**self.args)
                result=asyncio.run(invoker.invoke(target=TARGET,turn=packet.turn,
                    max_cost_usd=Decimal('1'),decision_schema_version='1'))
                self.assertEqual(packet.validate_decision(result.decision)['status'],'PROPOSAL_ONLY')
                # A proposal is not applied/tested work and cannot unlock review.
                return {'status':'STOPPED','worker_invocations':1,'release_dispatched':False}
            return SimpleNamespace(activation=task,tick=tick)
        with TemporaryDirectory() as tmp, patch('socket.create_connection',side_effect=AssertionError('network forbidden')):
            queue=LocalTaskQueue(Path(tmp)/'queue.db')
            admission=AuthenticatedTaskAdmission(queue,verifier=FixtureVerifier(payload),clock=lambda:now)
            admission.admit(payload,b'x'*64,**args);queue.pause(False)
            runner=GenericTaskRunner(queue,admission.scheduler_resolver(scheduler),enabled=True)
            self.assertEqual(runner.tick()['status'],'STOPPED')
            self.assertEqual(runner.tick()['status'],'IDLE_OR_PAUSED')
            self.assertEqual(queue.inspect('entry-1')['status'],'PENDING')
        self.assertEqual(transport.calls,1)
        self.assertEqual(credentials.calls,1)  # Fake in-memory credentials only.


if __name__=='__main__': unittest.main()


class NewFilesOnlyTaskTests(unittest.TestCase):
    """A task that only creates files (e.g. bonus-library-ai-cover-prompt) reaches the builder."""
    def setUp(self):
        root = Path(__file__).resolve().parents[1]
        self.raw = (root/'factory/projects/bonus-library-ai-cover-prompt/task.json').read_bytes()
        self.spec = json.loads(self.raw)
        self.task = QueuedTask('ai-cover-prompt-001', 'development-local', self.spec['task_id'],
            'ai-cover-prompt-001', 'a'*40, digest(self.raw), 'IMPLEMENTATION')

    def protocol(self, files, missing):
        return TaskImplementationProtocol(self.task, repository=self.spec['repository'],
            target_commit=self.spec['target_commit'], contract_bytes=self.raw,
            files=files, missing_paths=missing)

    def test_only_missing_paths_is_accepted_and_new_files_validate(self):
        protocol = self.protocol({}, self.spec['allowed_paths'])
        self.assertEqual(protocol.turn['files'], {})
        decision = {'type': 'apply_edits', 'summary': 'Add cover core', 'edits': [
            {'path': p, 'old_text': '', 'new_text': 'export {};\n'} for p in self.spec['allowed_paths']]}
        protocol.validate_decision(decision)

    def test_nothing_to_change_is_still_rejected(self):
        with self.assertRaises(StateError):
            self.protocol({}, [])
