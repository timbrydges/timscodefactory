import json
import os
import sys
import tempfile
import unittest
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

    def test_package_contains_exact_contract_and_evidence(self):
        paths = contract_paths()
        self.assertIn('factory/autonomy/operating-contract.yaml', paths)
        self.assertIn('factory/schemas/autonomy-operating-contract.schema.json', paths)
        self.assertIn('factory/evidence/autonomy-financial-authorization-2026-09-23.json', paths)
        self.assertIn('factory/evidence/openai-gpt-5.6-sol-pricing-reference-2026-09-23.json', paths)


if __name__ == '__main__':
    unittest.main()
