import json
import os
import shutil
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))
sys.path.insert(0, str(ROOT / 'scripts'))

from factory_runtime.acceptance_broker_lambda import handler, handle_probe
from factory_state.model import StateError
from build_acceptance_broker_package import contract_paths


COMMIT = 'a' * 40
EVENT = {'kind': 'acceptance_broker_probe', 'source_commit': COMMIT,
         'nonce': 'probe-1234567890', 'task_id': 'deterministic-text-fingerprint'}


class AcceptanceBrokerLambdaTests(unittest.TestCase):
    def test_probe_has_no_model_or_release_authority(self):
        reply = handle_probe(EVENT, source_commit=COMMIT, enabled='false')
        self.assertEqual(reply['provider_calls'], 0)
        self.assertFalse(reply['credentials_read'])
        self.assertFalse(reply['release_dispatched'])

    def test_kill_switch_and_other_events_fail_closed(self):
        for value in ('', 'true', 'FALSE'):
            with self.subTest(value=value), self.assertRaisesRegex(StateError, 'kill switch'):
                handle_probe(EVENT, source_commit=COMMIT, enabled=value)
        for changed in ({'kind': 'acceptance_provider_call'},
                        {'source_commit': 'b' * 40}, {'unexpected': 1}):
            with self.subTest(changed=changed), self.assertRaises(StateError):
                handle_probe({**EVENT, **changed}, source_commit=COMMIT, enabled='false')

    def test_handler_requires_build_identity_and_explicit_disabled_flag(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'BUILD.json').write_text(json.dumps({'source_commit': COMMIT}))
            for name in contract_paths():
                target = root / name
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(ROOT / name, target)
            with patch.dict(os.environ, {'LAMBDA_TASK_ROOT': directory,
                                      'FACTORY_ACCEPTANCE_BROKER_ENABLED': 'false'}):
                self.assertEqual(handler(EVENT, None)['provider_calls'], 0)
            with patch.dict(os.environ, {'LAMBDA_TASK_ROOT': directory}, clear=True):
                with self.assertRaises(StateError):
                    handler(EVENT, None)
            (root / 'BUILD.json').write_text('{}')
            with patch.dict(os.environ, {'LAMBDA_TASK_ROOT': directory,
                                      'FACTORY_ACCEPTANCE_BROKER_ENABLED': 'false'}):
                with self.assertRaisesRegex(StateError, 'build identity'):
                    handler(EVENT, None)

    def test_live_route_stops_at_pending_contract_gates_before_credential_io(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'BUILD.json').write_text(json.dumps({'source_commit': COMMIT}))
            for name in contract_paths():
                target = root / name
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(ROOT / name, target)
            now = datetime.now(timezone.utc)
            activation = {'activation_id':'test-acceptance-1',
                          'factory_id':'tims-software-factory',
                          'task_id':'deterministic-text-fingerprint',
                          'source_commit':COMMIT,
                          'contract_digest':'sha256:' +
                          '7ca5363f88bc43e31436e1c8640bb9516a705aa07dda82519a690a9301a9b9fa',
                          'starts_at':now.isoformat(),
                          'expires_at':(now + timedelta(minutes=5)).isoformat()}
            with patch.dict(os.environ, {'LAMBDA_TASK_ROOT': directory,
                    'FACTORY_ACCEPTANCE_BROKER_ENABLED':'true',
                    'FACTORY_ACCEPTANCE_ACTIVATION_JSON':json.dumps(activation),
                    'FACTORY_OPENAI_SECRET_ARN':'arn:aws:secretsmanager:ca-central-1:'
                    '666730517561:secret:tims-software-factory/provider/openai/acceptance-WE57Tw'}):
                with self.assertRaisesRegex(StateError, 'activation differs'):
                    handler({'kind':'acceptance_provider_call'}, None)

    def test_packaged_broker_remains_disabled_even_with_valid_probe(self):
        with patch('factory_runtime.acceptance_broker_service.AcceptanceBrokerService') as service:
            service.return_value.handle.side_effect = StateError('acceptance broker is disabled')
            reply = handle_probe(EVENT, source_commit=COMMIT, enabled='false')
            self.assertFalse(reply['broker_enabled'])
            self.assertEqual(reply['provider_calls'], 0)
            self.assertFalse(service.call_args.kwargs['enabled'])
            service.return_value.handle.assert_called_once_with({})

    def test_package_contains_exact_contract_and_evidence(self):
        paths = contract_paths()
        self.assertIn('factory/autonomy/operating-contract.yaml', paths)
        self.assertIn('factory/schemas/autonomy-operating-contract.schema.json', paths)
        self.assertIn('factory/evidence/autonomy-financial-authorization-2026-09-23.json', paths)
        self.assertIn('factory/evidence/openai-gpt-5.6-sol-pricing-quote-2026-10-01.json', paths)


if __name__ == '__main__':
    unittest.main()
