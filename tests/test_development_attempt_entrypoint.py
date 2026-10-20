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
