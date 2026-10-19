import importlib.util
from pathlib import Path
from unittest import TestCase
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('development_attempt',
    Path(__file__).resolve().parents[1]/'scripts/development_attempt.py')
entry = importlib.util.module_from_spec(spec)
spec.loader.exec_module(entry)


class EntrypointTests(TestCase):
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
