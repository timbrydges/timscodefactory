import importlib.util
from pathlib import Path
from unittest import TestCase
from unittest.mock import patch
from unittest.mock import AsyncMock
from types import SimpleNamespace
import asyncio
import json
import tempfile
from datetime import datetime, timedelta, timezone
from unittest.mock import Mock
from factory_runtime.credential_issuance import CredentialIssuanceLedger, IssuanceAuthorization
from factory_runtime.provider_broker_service import ResolvedProviderTarget

spec = importlib.util.spec_from_file_location('development_attempt',
    Path(__file__).resolve().parents[1]/'scripts/development_attempt.py')
entry = importlib.util.module_from_spec(spec)
spec.loader.exec_module(entry)


class EntrypointTests(TestCase):
    def test_failed_and_uncertain_results_exit_unsuccessfully(self):
        for status in ('NEEDS_RECONCILIATION', 'REJECTED', 'STOPPED', 'IDLE_OR_PAUSED'):
            with self.subTest(status=status), patch('builtins.print') as output:
                self.assertEqual(entry.report_result({'status': status}), 1)
                output.assert_called_once()
        with patch('builtins.print'):
            self.assertEqual(entry.report_result({'status': 'TICK_COMPLETED'}), 0)

    def test_default_has_no_subprocess_or_host_construction(self):
        with patch.object(entry, 'compose_bonus_host') as host, patch.object(entry, 'subprocess') as process:
            self.assertEqual(entry.main([]), 0)
            host.assert_not_called()
            self.assertEqual(process.mock_calls, [])

    def test_execution_requires_both_owner_and_exact_inputs(self):
        with patch.object(entry, 'compose_bonus_host') as host, patch.object(entry, 'subprocess') as process:
            with self.assertRaises(SystemExit): entry.main(['--execute-approved-once'])
            host.assert_not_called()
            self.assertEqual(process.mock_calls, [])

    def test_disabled_profile_option_does_not_read_file_or_construct_generic_host(self):
        with patch.object(entry, 'compose_task_host') as host, patch.object(entry, 'read_execution_profile') as read:
            with patch.object(entry, 'subprocess') as process:
                self.assertEqual(entry.main(['--execution-profile', 'not-present.json']), 0)
                self.assertEqual(process.mock_calls, [])
            read.assert_not_called()
            host.assert_not_called()

    def test_disabled_entrypoint_does_not_consume_injected_binding(self):
        with patch.object(entry, 'execute', new_callable=AsyncMock) as execute:
            self.assertEqual(entry.main([], credential_binding=object()), 0)
            execute.assert_not_awaited()

    def test_cli_identity_bootstrap_is_gated_and_passes_only_trusted_binding(self):
        with patch.object(entry, 'binding_from_configuration', return_value=object()) as bind, \
                patch.object(entry, 'execute', new_callable=AsyncMock,
                             return_value={'status':'TICK_COMPLETED'}) as execute:
            identity = ['--identity-config','operator.json','--identity-config-sha256','sha256:fake']
            self.assertEqual(entry.main(identity), 0)
            bind.assert_not_called()
            with self.assertRaises(SystemExit):
                entry.main(['--execute-approved-once']+identity)
            bind.assert_not_called()
            args = ['--execute-approved-once','--owner-authorized']
            for flag in ('pins','approval','pricing','contract','repository-path','attempt-directory'):
                args += ['--'+flag, 'unused']
            self.assertEqual(entry.main(args+identity), 0)
            bind.assert_called_once()
            self.assertIs(execute.call_args.kwargs['credential_binding'], bind.return_value)

    def test_missing_or_untrusted_binding_stops_before_subprocess(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root/'pins.json').write_text(json.dumps({'credential_source': 'wif:sha256:'+'a'*64}))
            (root/'approval.json').write_text('{}')
            args = SimpleNamespace(owner_authorized=True, pins=root/'pins.json',
                approval=root/'approval.json', execution_profile=root/'profile.json')
            for binding in (None, object()):
                with self.subTest(binding=binding), patch.object(entry, 'subprocess') as process:
                    with self.assertRaises(ValueError):
                        asyncio.run(entry.execute(args, credential_binding=binding))
                    self.assertEqual(process.mock_calls, [])

    def test_owner_gate_precedes_binding_and_file_access(self):
        with patch.object(entry, 'subprocess') as process:
            with self.assertRaises(ValueError):
                asyncio.run(entry.execute(SimpleNamespace(owner_authorized=False),
                                          credential_binding=object()))
            self.assertEqual(process.mock_calls, [])

    def test_valid_binding_reaches_generic_host_without_exchange(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            now = datetime.now(timezone.utc)
            authorization = IssuanceAuthorization('sha256:'+'e'*64, 'test-idp', 'test-sa',
                ResolvedProviderTarget('openai', 'gpt-5.6-sol', 'development-pinned-v1'),
                now, now+timedelta(hours=1), 2, ('api.model.request',))
            exchange = AsyncMock()
            binding = entry.RenewableCredentialBinding(
                CredentialIssuanceLedger(root/'issuance.db', authorization,
                                         operator_authorized=True), exchange)
            contract = b'{"task_id":"offline-test"}'
            pins = dict(credential_source=binding.source_pin, source_commit='abc',
                attempt_id='job-1', contract_digest=entry.digest(contract),
                repository='owner/repo', target_commit='def', image_ref='unused')
            for name, data in [('pins', pins), ('approval', {}), ('pricing', {}),
                               ('profile', {})]:
                (root/(name+'.json')).write_text(json.dumps(data))
            (root/'contract.json').write_bytes(contract)
            args = SimpleNamespace(owner_authorized=True, pins=root/'pins.json',
                approval=root/'approval.json', pricing=root/'pricing.json',
                execution_profile=root/'profile.json', contract=root/'contract.json',
                repository_path=root, attempt_directory=root/'job-1')
            profile = Mock()
            host = Mock(tick=AsyncMock(return_value={'status':'TICK_COMPLETED'}))
            with patch.object(entry, 'subprocess') as process, \
                    patch.object(entry, 'read_execution_profile', return_value=profile), \
                    patch.object(entry, 'read_repository_snapshot', return_value=object()), \
                    patch.object(entry, 'PinnedPricing'), \
                    patch.object(entry, 'compose_task_host', return_value=host) as compose:
                process.check_output.side_effect = ['abc', '']
                result = asyncio.run(entry.execute(args, credential_binding=binding))
                self.assertEqual(result['status'], 'TICK_COMPLETED')
                self.assertIs(compose.call_args.kwargs['credential_binding'], binding)
                profile.validate_binding.assert_called_once()
                host.tick.assert_awaited_once()
            exchange.assert_not_awaited()
            for source, profile_path in (
                    ('env:FACTORY_OPENAI_API_KEY', root/'profile.json'),
                    (binding.source_pin, None)):
                with self.subTest(source=source, profile=profile_path):
                    pins['credential_source'] = source
                    args.pins.write_text(json.dumps(pins))
                    args.execution_profile = profile_path
                    with patch.object(entry, 'subprocess') as process:
                        with self.assertRaises(ValueError):
                            asyncio.run(entry.execute(args, credential_binding=binding))
                        self.assertEqual(process.mock_calls, [])
                    exchange.assert_not_awaited()


class PrivateSourceEntrypointTests(TestCase):
    def setUp(self):
        import hashlib
        tmp = tempfile.TemporaryDirectory(); self.addCleanup(tmp.cleanup)
        root = self.root = Path(tmp.name).resolve()
        raw = json.dumps(dict(schema=1, app_client_id='Iv23offlineOnly', installation_id=77,
            repository='owner/private', repository_id=123, git_executable=str(root/'git'),
            signer_executable=str(root/'openssl'), key_path=str(root/'k.pem'),
            public_fingerprint='SHA256:'+'A'*43+'=', attempt_parent=str(root/'attempts'))).encode()
        (root/'source.json').write_bytes(raw)
        self.source_digest = 'sha256:'+hashlib.sha256(raw).hexdigest()
        contract = b'{"task_id":"task"}'
        (root/'contract.json').write_bytes(contract)
        self.pins = dict(credential_source='env:FACTORY_OPENAI_API_KEY', source_commit='c'*40,
            attempt_id='attempt-1', contract_digest=entry.digest(contract), repository='owner/private',
            target_commit='a'*40, image_ref='image@sha256:'+'b'*64,
            source_config_digest=self.source_digest, source_manifest_digest='sha256:'+'d'*64)
        self.pins.update(model_id='gpt-5.6-sol', builder_cap='0.25', reviewer_cap='0.25',
                         total_cap='0.50', max_request_bytes=42020, max_output_tokens=4096)
        (root/'pricing.json').write_text('{}')
        self.events = []

    def args(self, **changes):
        pins = dict(self.pins, **changes.pop('pins', {}))
        (self.root/'pins.json').write_text(json.dumps(pins))
        approval = changes.pop('approval_pins', pins)
        (self.root/'approval.json').write_text(json.dumps({'pins': approval,
            'expires_at': '2099-01-01T00:00:00+00:00'}))
        values = dict(owner_authorized=True, pins=self.root/'pins.json',
            approval=self.root/'approval.json', pricing=self.root/'pricing.json',
            contract=self.root/'contract.json', attempt_directory=self.root/'attempt-1',
            execution_profile=None, repository_path=None, source_config=self.root/'source.json',
            source_config_sha256=self.source_digest)
        values.update(changes)
        return SimpleNamespace(**values)

    def execute(self, args, docker_error=None):
        process = Mock()
        process.check_output.side_effect = lambda command, **kw: 'c'*40 if 'rev-parse' in command else ''
        def docker(*a, **kw):
            self.events.append('docker')
            if docker_error: raise docker_error
        process.run.side_effect = docker
        def acquire(*a, **kw):
            self.events.append('acquire'); return 'snapshot'
        host = SimpleNamespace(tick=AsyncMock(return_value={'status': 'TICK_COMPLETED'}))
        with patch.object(entry, 'subprocess', process), \
                patch.object(entry, 'PinnedPricing'), \
                patch.object(entry.private_source, 'acquire_private_source', side_effect=acquire) as acq, \
                patch.object(entry, 'read_repository_snapshot') as local, \
                patch.object(entry, 'compose_bonus_host', return_value=host) as compose:
            try:
                return asyncio.run(entry.execute(args)), acq, compose, local
            except Exception as error:
                return error, acq, compose, local

    def test_cli_requires_exactly_one_pinned_source(self):
        base = ['--execute-approved-once', '--owner-authorized']
        for flag in ('pins', 'approval', 'pricing', 'contract', 'attempt-directory'):
            base += ['--'+flag, 'unused']
        source = ['--source-config', 'source.json', '--source-config-sha256', 'sha256:x']
        for argv in (base, base+['--repository-path', 'r']+source, base+source[:2],
                     base+['--repository-path', 'r', '--source-config-sha256', 'sha256:x']):
            with self.subTest(argv=argv), patch.object(entry, 'execute', new_callable=AsyncMock) as run, \
                    patch('sys.stderr'), self.assertRaises(SystemExit):
                entry.main(argv)
            run.assert_not_awaited()

    def test_acquires_once_after_local_checks_with_pinned_binding(self):
        result, acquire, compose, local = self.execute(self.args())
        self.assertEqual(result, {'status': 'TICK_COMPLETED'})
        self.assertEqual(self.events, ['docker', 'acquire'])
        config, binding, name = acquire.call_args.args
        self.assertEqual((binding.repository, binding.repository_id, binding.commit,
                          binding.manifest_digest), ('owner/private', 123, 'a'*40, 'sha256:'+'d'*64))
        self.assertEqual(name, 'attempt-1')
        self.assertIs(acquire.call_args.kwargs['enabled'], True)
        self.assertEqual(compose.call_args.kwargs['snapshot'], 'snapshot')
        local.assert_not_called()

    def test_unpinned_or_mismatched_source_never_acquires(self):
        cases = (dict(pins={'source_config_digest': 'sha256:'+'0'*64}),
                 dict(pins={'source_manifest_digest': None}),
                 dict(source_config_sha256='sha256:'+'0'*64),
                 dict(pins={'repository': 'owner/other'}),
                 dict(repository_path=self.root),
                 dict(approval_pins={**self.pins, 'source_manifest_digest': 'sha256:'+'e'*64}),
                 dict(pins={'source_manifest_digest': None}, approval_pins=self.pins))
        for change in cases:
            with self.subTest(change=change):
                pins = dict(self.pins, **change.get('pins', {}))
                pins = {k: v for k, v in pins.items() if v is not None}
                self.pins, saved = pins, self.pins
                result, acquire, compose, _ = self.execute(self.args(**{k: v for k, v in change.items() if k != 'pins'}))
                self.pins = saved
                self.assertIsInstance(result, Exception)
                acquire.assert_not_called(); compose.assert_not_called()
                self.assertNotIn('docker', self.events)

    def test_failed_image_check_prevents_acquisition(self):
        result, acquire, compose, _ = self.execute(self.args(), docker_error=OSError('no image'))
        self.assertIsInstance(result, OSError)
        acquire.assert_not_called(); compose.assert_not_called()


class StoppedReportTests(TestCase):
    def test_only_fixed_factory_reasons_are_reported(self):
        from factory_state.model import StateError
        self.assertEqual(entry.stopped_report(StateError('lease expired before fetch')),
            {'status': 'STOPPED', 'error_type': 'StateError', 'reason': 'lease expired before fetch'})
        self.assertEqual(entry.stopped_report(RuntimeError('sk-secret body')),
            {'status': 'STOPPED', 'error_type': 'RuntimeError'})

