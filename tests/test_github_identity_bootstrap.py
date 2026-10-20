from datetime import datetime, timedelta, timezone
import hashlib
import importlib.util
import json
from pathlib import Path
import sqlite3
import tempfile
from unittest import TestCase
from unittest.mock import patch

from factory_runtime.github_identity_bootstrap import (
    binding_from_configuration, open_ledger, read_configuration)
from factory_runtime.provider_credentials import ProviderCredentialLeaseError


class BootstrapTests(TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.now = datetime(2026, 10, 20, tzinfo=timezone.utc)
        self.path = self.root/'identity.json'
        self.data = dict(schema=1, ledger_path=str(self.root/'issuance.db'),
            policy=dict(request_origin='https://pipelines.actions.githubusercontent.com',
                audience='https://api.openai.com/v1', repository='owner/control',
                repository_id='123', ref='refs/heads/main',
                workflow_ref='owner/control/.github/workflows/runner.yml@refs/heads/main'),
            authorization=dict(identity_provider_id='fake-idp', service_account_id='fake-sa',
                target=dict(provider_family='openai', model_id='fake-model', selector_version='v1'),
                starts_at=self.now.isoformat(), expires_at=(self.now+timedelta(hours=1)).isoformat(),
                maximum_exchanges=2, scopes=['api.model.request'], minimum_interval_seconds=90))
        self.save()

    def save(self):
        raw = json.dumps(self.data).encode()
        self.path.write_bytes(raw)
        self.digest = 'sha256:'+hashlib.sha256(raw).hexdigest()

    def config(self):
        return read_configuration(self.path, self.digest, owner_authorized=True)

    def binding(self, **kwargs):
        return binding_from_configuration(self.path, self.digest, clock=lambda:self.now,
                                           owner_authorized=True, **kwargs)

    def test_disabled_binding_and_owner_gate_do_not_read_configuration(self):
        with patch.object(Path, 'open') as read:
            self.assertIsNone(self.binding())
            with self.assertRaises(ValueError):
                read_configuration(self.path, self.digest)
            read.assert_not_called()

    def test_digest_covers_policy_and_absolute_ledger_location(self):
        before = self.config().authorization.approval_digest
        for key, value in [('repository_id','456'), ('request_origin','https://other.actions.githubusercontent.com')]:
            self.data['policy'][key] = value
            self.path.write_text(json.dumps(self.data))
            with self.assertRaises(ValueError):
                self.config()
            self.save()
            self.assertNotEqual(before, self.config().authorization.approval_digest)

    def test_configuration_read_never_creates_ledger(self):
        config = self.config()
        self.assertFalse(config.ledger_path.exists())
        with self.assertRaises(ValueError):
            self.binding(enabled=True)
        self.assertFalse(config.ledger_path.exists())

    def test_initialize_is_exclusive_paused_and_has_no_environment_access(self):
        config = self.config()
        with patch('factory_runtime.github_identity_bootstrap.os.getenv') as env:
            ledger = open_ledger(config, initialize=True)
            with self.assertRaises(ProviderCredentialLeaseError):
                ledger.claim(now=self.now, target=config.authorization.target)
            binding = self.binding(enabled=True)
            self.assertEqual(binding.ledger.path, ledger.path)
            env.assert_not_called()
            with self.assertRaises(FileExistsError):
                open_ledger(config, initialize=True)

    def test_reopening_never_resumes_or_clears_consumed_claim(self):
        config = self.config()
        ledger = open_ledger(config, initialize=True)
        ledger.pause(False)
        claim = ledger.claim(now=self.now, target=config.authorization.target)
        reopened = self.binding(enabled=True).ledger
        with self.assertRaises(ProviderCredentialLeaseError):
            reopened.claim(now=self.now+timedelta(seconds=180), target=config.authorization.target)
        reopened.finish(claim, now=self.now, succeeded=False)
        ledger.pause(True)
        with self.assertRaises(ProviderCredentialLeaseError):
            self.binding(enabled=True).ledger.claim(now=self.now, target=config.authorization.target)

    def test_empty_or_unrelated_existing_file_is_not_initialized(self):
        config = self.config()
        config.ledger_path.write_bytes(b'')
        with self.assertRaises(sqlite3.DatabaseError):
            self.binding(enabled=True)
        self.assertEqual(config.ledger_path.read_bytes(), b'')

    def test_policy_change_cannot_rebind_existing_ledger(self):
        open_ledger(self.config(), initialize=True)
        self.data['policy']['repository_id'] = '456'
        self.save()
        with self.assertRaises(ValueError):
            self.binding(enabled=True)

    def test_relative_path_and_extra_fields_rejected(self):
        self.data['ledger_path'] = 'issuance.db'
        self.save()
        with self.assertRaises(ValueError):
            self.config()
        self.data['ledger_path'] = str(self.root/'issuance.db')
        self.data['transport'] = 'arbitrary-code'
        self.save()
        with self.assertRaises(ValueError):
            self.config()

    def test_local_cli_defaults_disabled_and_initializes_only_paused(self):
        file = Path(__file__).resolve().parents[1]/'scripts/development_identity.py'
        spec = importlib.util.spec_from_file_location('identity_cli', file)
        cli = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cli)
        with patch.object(cli, 'read_configuration') as read:
            self.assertEqual(cli.main([]), 0)
            read.assert_not_called()
        with patch('factory_runtime.github_identity_bootstrap.os.getenv') as env:
            self.assertEqual(cli.main(['--owner-authorized','--action','initialize-paused',
                '--identity-config',str(self.path),'--identity-config-sha256',self.digest]), 0)
            env.assert_not_called()
        with self.assertRaises(ProviderCredentialLeaseError):
            open_ledger(self.config()).claim(now=self.now, target=self.config().authorization.target)
