from dataclasses import replace
from datetime import datetime, timezone
import json
from types import SimpleNamespace
from unittest import TestCase
from unittest.mock import Mock, patch

from factory_runtime.development_profile import TaskExecutionProfile
from factory_runtime.development_composition import compose_task_host
from factory_state.model import StateError


class ProfileTests(TestCase):
    def setUp(self):
        self.profile = TaskExecutionProfile('example/real-project', 'search-feature',
            ('src/search.py', 'tests/test_search.py'), ('python', '-m', 'unittest'), 45)
        self.pins = dict(execution_profile_digest=self.profile.digest,
            repository=self.profile.repository, credential_source='env:FACTORY_OPENAI_API_KEY',
            model_id='gpt-5.6-sol', image_ref='sha256:'+'a'*64,
            max_request_bytes=42020, max_output_tokens=8192,
            builder_cap='0.25', reviewer_cap='0.25', total_cap='0.50')
        self.spec = dict(repository=self.profile.repository, task_id=self.profile.task_id,
                         allowed_paths=list(self.profile.required_changed_paths))
        self.task = SimpleNamespace(task_id=self.profile.task_id, activation_id='test')

    def compose(self, profile=None, authorized=True):
        return compose_task_host('unused', profile=profile or self.profile, approval={},
            expected_pins=self.pins, receipt_path='unused', task=self.task,
            contract_bytes=json.dumps(self.spec).encode(), snapshot=None,
            pricing_source=Mock(), clock=lambda: datetime.now(timezone.utc),
            owner_authorized=authorized)

    def test_arbitrary_repo_uses_same_provider_and_exact_profile_request(self):
        with patch('factory_runtime.development_composition.compose_approved_host') as host:
            self.compose()
            options = host.call_args.kwargs
            self.assertEqual(options['delivery'], self.profile.delivery)
            self.assertIs(options['execution_profile'], self.profile)
            candidate = Mock()
            options['request_for'](candidate)
            request = candidate.request.call_args.kwargs
            self.assertEqual(request['command'], ('python', '-m', 'unittest'))
            self.assertEqual(request['timeout_seconds'], 45)
            self.assertEqual(request['request_id'], 'task-tests')
            self.assertIs(options['builder'].credential_source, options['reviewer'].credential_source)

    def test_changed_command_timeout_or_scope_requires_new_pin(self):
        for profile in (
            replace(self.profile, test_command=('python', 'different.py')),
            replace(self.profile, timeout_seconds=46),
            replace(self.profile, required_changed_paths=('src/search.py',)),
        ):
            with self.subTest(profile=profile):
                with patch('factory_runtime.development_composition.compose_approved_host') as host:
                    with self.assertRaises(StateError): self.compose(profile)
                    host.assert_not_called()

    def test_other_task_repository_and_out_of_contract_scope_stop_before_host(self):
        for key, value in [('task_id', 'other'), ('repository', 'example/other'),
                           ('allowed_paths', ['src/search.py'])]:
            old = self.spec[key]
            self.spec[key] = value
            with patch('factory_runtime.development_composition.compose_approved_host') as host:
                with self.assertRaises(StateError): self.compose()
                host.assert_not_called()
            self.spec[key] = old

    def test_no_authorization_and_missing_digest_stop_before_host(self):
        with patch('factory_runtime.development_composition.compose_approved_host') as host:
            with self.assertRaises(StateError): self.compose(authorized=False)
            self.pins.pop('execution_profile_digest')
            with self.assertRaises(StateError): self.compose()
            host.assert_not_called()

    def test_profile_rejects_mutable_scope_traversal_and_unbounded_execution(self):
        for changes in (
            dict(required_changed_paths=['src/search.py']),
            dict(required_changed_paths=('../escape',)),
            dict(test_command=('python', chr(0))),
            dict(timeout_seconds=61), dict(timeout_seconds=True),
        ):
            with self.subTest(changes=changes):
                with self.assertRaises(StateError): replace(self.profile, **changes)

    def test_returned_delivery_cannot_mutate_profile_or_digest(self):
        before = self.profile.digest
        exposed = self.profile.delivery
        exposed['test_command'].append('unapproved')
        exposed['required_changed_paths'].clear()
        self.assertEqual(self.profile.digest, before)
        self.assertEqual(self.profile.test_command, ('python', '-m', 'unittest'))

    def test_operator_document_has_exact_keys_types_and_no_duplicate_fields(self):
        from factory_runtime.development_profile import read_execution_profile
        data = dict(repository=self.profile.repository, task_id=self.profile.task_id,
            required_changed_paths=list(self.profile.required_changed_paths),
            test_command=list(self.profile.test_command), timeout_seconds=45)
        self.assertEqual(read_execution_profile(json.dumps(data).encode()), self.profile)
        for raw in (
            b'{"repository":"a/b","repository":"c/d"}',
            json.dumps(dict(data, surprise=True)).encode(),
            json.dumps(dict(data, test_command='python')).encode(),
            b' ' * 16385, b'null', b'[]', b'bad',
        ):
            with self.subTest(raw=raw[:100]):
                with self.assertRaises(StateError): read_execution_profile(raw)
