import asyncio
import json
from pathlib import Path
import unittest

from factory_runtime.task_provider import TaskImplementationProtocol
from factory_runtime.task_candidate import candidate_workspace
from factory_runtime.task_queue import QueuedTask
from factory_runtime.repository_snapshot import RepositoryFile, RepositorySnapshot
from factory_runtime.worker import digest
from factory_runtime.openai_provider import OpenAIProviderPolicy, OpenAIResponsesProviderInvoker, ProviderHTTPResponse
from factory_state.model import StateError


class TaskNewFileTests(unittest.TestCase):
    def setUp(self):
        self.raw = (Path(__file__).resolve().parents[1]/
                    'factory/projects/bonus-library-pagination/task.json').read_bytes()
        self.spec = json.loads(self.raw)
        self.page = 'src/app/dashboard/page.tsx'
        self.helper = 'src/lib/library-pagination.ts'
        self.test = 'tests/library-pagination.test.mjs'
        self.files = {self.page: 'const pageSize = 10;\n'}
        self.task = QueuedTask('entry','factory',self.spec['task_id'],'activation','a'*40,
                               digest(self.raw),'IMPLEMENTATION')
        self.args = dict(repository=self.spec['repository'],target_commit=self.spec['target_commit'],
                         contract_bytes=self.raw,files=self.files)
        self.protocol = TaskImplementationProtocol(self.task,**self.args,missing_paths=[self.helper,self.test])
        self.snapshot = RepositorySnapshot(self.spec['repository'],self.spec['target_commit'],
            (RepositoryFile(self.page,self.files[self.page].encode(),False),
             RepositoryFile('package.json',b'{}',False)))
        # These are fixture source strings, not a pagination implementation.
        self.decision = {'type':'apply_edits','summary':'Fixture files', 'edits':[
            {'path':self.helper,'old_text':'','new_text':'export const pageSize = 10;\n'},
            {'path':self.test,'old_text':'','new_text':'// fixture test source\n'},
            {'path':self.page,'old_text':'10','new_text':'20'}]}

    def test_scoped_files_created_in_disposable_candidate_only(self):
        with candidate_workspace(self.protocol,self.decision,repository_snapshot=self.snapshot) as candidate:
            root = candidate.workspace
            self.assertEqual((root/self.helper).read_bytes(),b'export const pageSize = 10;\n')
            self.assertEqual((root/self.test).read_bytes(),b'// fixture test source\n')
            self.assertEqual((root/self.page).read_bytes(),b'const pageSize = 20;\n')
            self.assertEqual((root/'package.json').read_bytes(),b'{}')
        self.assertFalse(root.exists())
        self.assertEqual(self.files[self.page],'const pageSize = 10;\n')

    def test_creation_requires_complete_snapshot(self):
        with self.assertRaises(StateError):
            with candidate_workspace(self.protocol,self.decision): self.fail('must reject')

    def test_existing_file_cannot_be_overwritten_as_new(self):
        from dataclasses import replace
        snapshot = replace(self.snapshot,files=self.snapshot.files+(RepositoryFile(self.helper,b'original',False),))
        with self.assertRaises(StateError):
            with candidate_workspace(self.protocol,self.decision,repository_snapshot=snapshot): self.fail('must reject')

    def test_case_alias_and_file_parent_collisions_fail_before_write(self):
        from dataclasses import replace
        for path in ['SRC/lib/other.ts','src/lib',self.helper.upper()]:
            snapshot = replace(self.snapshot,files=self.snapshot.files+(RepositoryFile(path,b'original',False),))
            with self.subTest(path=path),self.assertRaises(StateError):
                with candidate_workspace(self.protocol,self.decision,repository_snapshot=snapshot): self.fail('must reject')

    def test_undeclared_creation_and_empty_replacement_rejected(self):
        protocol = TaskImplementationProtocol(self.task,**self.args)
        for item in [{'path':self.helper,'old_text':'','new_text':'new'},
                     {'path':self.page,'old_text':'','new_text':'overwrite'},
                     {'path':'.env','old_text':'','new_text':'new'}]:
            with self.subTest(item=item),self.assertRaises(StateError):
                protocol.validate_decision({**self.decision,'edits':[item]})

    def test_new_file_old_text_nonempty_content_empty_and_duplicates_rejected(self):
        for edits in [[{'path':self.helper,'old_text':'old','new_text':'new'}],
                      [{'path':self.helper,'old_text':'','new_text':''}],
                      [self.decision['edits'][0]]*2]:
            with self.subTest(edits=edits),self.assertRaises(StateError):
                self.protocol.validate_decision({**self.decision,'edits':edits})

    def test_missing_path_scope_and_input_digest_are_bound(self):
        for paths in [[self.helper,self.helper],[self.page],['.env'],'not-a-list']:
            with self.subTest(paths=paths),self.assertRaises(StateError):
                TaskImplementationProtocol(self.task,**self.args,missing_paths=paths)
        old = TaskImplementationProtocol(self.task,**self.args)
        self.assertNotEqual(old.input_digest,self.protocol.input_digest)
        paths = [self.helper]
        protocol = TaskImplementationProtocol(self.task,**self.args,missing_paths=paths)
        paths.append('.env')
        self.assertEqual(protocol.turn['missing_paths'],[self.helper])

    def test_missing_file_read_rejected(self):
        with self.assertRaises(StateError):
            self.protocol.validate_decision({'type':'read_files','paths':[self.helper]})

    def test_existing_provider_adapter_transports_creation_offline(self):
        from decimal import Decimal
        from test_openai_provider import (CountingCredentialSource, StaticPricingSource,
            RecordingTransport, provider_payload, TARGET)
        wire = {**self.decision,'paths':[],'reason':''}
        transport = RecordingTransport(ProviderHTTPResponse(200,json.dumps(provider_payload(wire)).encode()))
        invoker = OpenAIResponsesProviderInvoker(CountingCredentialSource(),StaticPricingSource(),transport,
            policy=OpenAIProviderPolicy(live_enabled=True,workload='task_implementation',max_output_tokens=512))
        result = asyncio.run(invoker.invoke(target=TARGET,turn=self.protocol.turn,
            max_cost_usd=Decimal('1'),decision_schema_version='1'))
        self.assertEqual(self.protocol.validate_decision(result.decision)['status'],'PROPOSAL_ONLY')
        self.assertEqual(transport.calls,1)
        self.assertIn('missing_paths',json.loads(transport.last_body)['instructions'])


if __name__ == '__main__': unittest.main()
