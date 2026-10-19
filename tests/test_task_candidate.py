from dataclasses import replace
from datetime import datetime, timezone
import json
from pathlib import Path
import unittest

from factory_runtime.task_candidate import candidate_workspace
from factory_runtime.task_provider import TaskImplementationProtocol
from factory_runtime.task_queue import QueuedTask
from factory_runtime.worker import digest
from factory_runtime.sandbox import SandboxReceipt, SandboxContractError
from factory_state.model import StateError


class TaskCandidateTests(unittest.TestCase):
    def setUp(self):
        self.raw = (Path(__file__).resolve().parents[1] /
                    'factory/projects/bonus-library-pagination/task.json').read_bytes()
        self.spec = json.loads(self.raw)
        self.path = 'src/app/dashboard/page.tsx'
        self.files = {self.path: 'const pageSize = 10;\n'}
        self.decision = {'type': 'apply_edits', 'summary': 'Fixture edit',
            'edits': [{'path': self.path, 'old_text': '10', 'new_text': '20'}]}
        self.protocol = self.protocol_for(self.files)
        self.now = datetime.now(timezone.utc)

    def protocol_for(self, files):
        task = QueuedTask('entry', 'factory', self.spec['task_id'], 'activation',
                          'a' * 40, digest(self.raw), 'IMPLEMENTATION')
        return TaskImplementationProtocol(task, repository=self.spec['repository'],
            target_commit=self.spec['target_commit'], contract_bytes=self.raw, files=files)

    def request(self, candidate):
        return candidate.request(request_id='offline-test', lease_id='fixture-lease',
            role_id='fixture-role', command=('node', '--test'), environment_digest='sha256:'+'b'*64,
            timeout_seconds=30, expected_runner_identity='fixture-runner')

    def receipt(self, request, **changes):
        # Observation double only: no sandbox, process, signing or model call.
        return SandboxReceipt(**{**dict(request_id=request.request_id, task_id=request.task_id,
            lease_id=request.lease_id, role_id=request.role_id, source_commit=request.source_commit,
            workspace_digest=request.workspace_digest, command_digest=request.command_digest,
            environment_digest=request.environment_digest, runner_identity=request.expected_runner_identity,
            sandbox_id='fixture-sandbox', started_at=self.now, finished_at=self.now, exit_code=0,
            timed_out=False, stdout_digest=digest(b''), stderr_digest=digest(b'')), **changes})

    def test_edits_only_disposable_copy_and_cleanup_on_success(self):
        with candidate_workspace(self.protocol, self.decision) as candidate:
            directory = candidate.workspace
            self.assertEqual((directory/self.path).read_bytes(), b'const pageSize = 20;\n')
            self.assertEqual(self.files[self.path], 'const pageSize = 10;\n')
            self.assertEqual(self.protocol.turn['files'], self.files)
        self.assertFalse(directory.exists())

    def test_cleanup_on_exception(self):
        with self.assertRaises(RuntimeError):
            with candidate_workspace(self.protocol, self.decision) as candidate:
                directory = candidate.workspace
                raise RuntimeError('fixture failure')
        self.assertFalse(directory.exists())

    def test_valid_observation_requires_review_and_grants_no_progression(self):
        with candidate_workspace(self.protocol, self.decision) as candidate:
            request = self.request(candidate)
            self.assertEqual(request.source_commit, self.spec['target_commit'])
            result = candidate.evaluate(request, self.receipt(request), now=self.now)
            self.assertEqual(result['status'], 'TESTS_PASSED_REVIEW_REQUIRED')
            self.assertFalse(result['authoritative'])
            self.assertFalse(result['progression_authorized'])
            self.assertFalse(result['release_authorized'])

    def test_failed_and_timed_out_tests_remain_distinct(self):
        with candidate_workspace(self.protocol, self.decision) as candidate:
            request = self.request(candidate)
            for changes, status in [({'exit_code': 1}, 'TESTS_FAILED'),
                                    ({'exit_code': None, 'timed_out': True}, 'TIMED_OUT')]:
                result = candidate.evaluate(request, self.receipt(request, **changes), now=self.now)
                self.assertEqual(result['status'], status)
                self.assertFalse(result['progression_authorized'])

    def test_receipt_binding_tampering_is_rejected(self):
        with candidate_workspace(self.protocol, self.decision) as candidate:
            request = self.request(candidate)
            for changes in [{'source_commit': 'c'*40}, {'workspace_digest': digest(b'wrong')},
                            {'command_digest': digest(b'wrong')}, {'runner_identity': 'other'},
                            {'environment_digest': digest(b'wrong')}]:
                with self.subTest(changes=changes), self.assertRaises(SandboxContractError):
                    candidate.evaluate(request, self.receipt(request, **changes), now=self.now)
            with self.assertRaises(StateError):
                candidate.evaluate(replace(request, task_id='other'), self.receipt(request), now=self.now)

    def test_changed_workspace_rejects_request_and_result(self):
        with candidate_workspace(self.protocol, self.decision) as candidate:
            request = self.request(candidate)
            (candidate.workspace/self.path).write_text('changed', encoding='utf-8')
            with self.assertRaises(StateError): self.request(candidate)
            with self.assertRaises(StateError):
                candidate.evaluate(request, self.receipt(request), now=self.now)

    def test_non_edits_and_stale_proposals_rejected(self):
        for decision in [{'type': 'read_files', 'paths': [self.path]},
                         {'type': 'escalate', 'reason': 'stop'},
                         {**self.decision, 'edits': [{'path': self.path, 'old_text': 'missing', 'new_text': 'x'}]}]:
            with self.subTest(decision=decision), self.assertRaises(StateError):
                with candidate_workspace(self.protocol, decision): self.fail('must not prepare')

    def test_nonportable_aliases_and_file_directory_collisions_rejected(self):
        from factory_runtime.task_candidate import _portable_paths
        for files in [{'CON.txt': ''}, {'a.': ''}, {'a': '', 'A': ''}, {'a': '', 'a/b': ''},
                      {'Src/a.ts': '', 'src/b.ts': ''},
                      {'../escape': ''}, {'/absolute': ''}, {'a\x00b': ''}, {'.git/config': ''}]:
            with self.subTest(files=files), self.assertRaises(StateError): _portable_paths(files)

    def test_mutable_inputs_cannot_change_prepared_candidate(self):
        with candidate_workspace(self.protocol, self.decision) as candidate:
            self.decision['edits'][0]['new_text'] = 'malicious'
            self.files[self.path] = 'changed'
            self.assertEqual((candidate.workspace/self.path).read_bytes(), b'const pageSize = 20;\n')

    def test_string_command_is_not_accepted_as_argv(self):
        with candidate_workspace(self.protocol, self.decision) as candidate:
            with self.assertRaises(StateError):
                candidate.request(request_id='r', lease_id='l', role_id='role', command='node --test',
                    environment_digest=digest(b'env'), timeout_seconds=30, expected_runner_identity='runner')


if __name__ == '__main__': unittest.main()
