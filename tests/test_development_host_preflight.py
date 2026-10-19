import importlib.util
import json
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest import TestCase
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('host_preflight',
    Path(__file__).resolve().parents[1] / 'scripts/development_host_preflight.py')
preflight = importlib.util.module_from_spec(spec)
spec.loader.exec_module(preflight)


class PreflightTests(TestCase):
    def test_pins_are_offline_and_do_not_claim_live_readiness(self):
        contract = {'repository': 'owner/repo', 'target_commit': 'a'*40,
            **{k: False for k in ('execution_authorized', 'spending_authorized',
                                 'signing_authorized', 'release_authorized')}}
        with TemporaryDirectory() as tmp:
            path = Path(tmp)/'task.json'
            path.write_text(json.dumps(contract))
            with patch.object(preflight, 'read_repository_snapshot', return_value=SimpleNamespace(
                    repository='owner/repo', commit='a'*40, files=())) as read:
                result = preflight.inspect(Path(tmp), path, 'sha256:'+'b'*64)
                self.assertFalse(result['enabled'])
                self.assertFalse(result['credential_read'])
                self.assertFalse(result['live_ready'])
                read.assert_called_once()
                contract['execution_authorized'] = True
                path.write_text(json.dumps(contract))
                with self.assertRaises(ValueError):
                    preflight.inspect(Path(tmp), path, 'sha256:'+'b'*64)
                self.assertEqual(read.call_count, 1)
