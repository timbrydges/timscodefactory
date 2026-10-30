from dataclasses import replace
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import tempfile
import traceback
import unittest

from factory_runtime.credential_issuance import CredentialIssuanceLedger, IssuanceAuthorization
from factory_runtime.identity_diagnostics import IdentityFailure, failure_receipt
from factory_runtime.provider_broker_service import ResolvedProviderTarget
from factory_runtime.provider_credentials import ProviderCredentialLeaseError
from factory_runtime.workload_identity_response import (
    ExchangeResponse, compose_exchange_credential_source, parse_exchange_response)


class ExchangeResponseTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.now = datetime(2026, 10, 20, tzinfo=timezone.utc)
        self.start = self.now
        self.data = dict(access_token='fake-response-secret-only',
            issued_token_type='urn:ietf:params:oauth:token-type:access_token', token_type='Bearer',
            expires_in=600, expires_at=int(self.now.timestamp()) + 600,
            scope='api.model.read api.model.request')
        self.scopes = ('api.model.read', 'api.model.request')
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / 'issuance.db'
        self.target = ResolvedProviderTarget('openai', 'test-model', 'v1')
        self.auth = IssuanceAuthorization('sha256:'+'a'*64, 'idp-test', 'sa-test', self.target,
            self.now, self.now + timedelta(hours=1), 2, self.scopes, 1)
        self.calls = 0

    def response(self):
        return ExchangeResponse(json.dumps(self.data).encode(), self.start + timedelta(hours=1))

    def parse(self, response=None, **kwargs):
        return parse_exchange_response(response or self.response(), requested_at=self.start,
            received_at=self.now, expected_scopes=kwargs.get('scopes', self.scopes))

    def ledger(self):
        return CredentialIssuanceLedger(self.path, self.auth, operator_authorized=True)

    async def exchange(self, auth):
        self.assertEqual(auth, self.auth)
        self.calls += 1
        return self.response()

    def source(self, ledger, enabled=True):
        return compose_exchange_credential_source(ledger=ledger, exchange=self.exchange,
            clock=lambda: self.now, enabled=enabled)

    def test_absolute_expiry_and_transport_delay(self):
        self.now += timedelta(seconds=35)
        lease = self.parse()
        self.assertEqual(lease.issued_at, self.start)
        self.assertEqual(lease.expires_at, self.start + timedelta(seconds=600))
        self.assertEqual((lease.expires_at - self.now).total_seconds(), 565)
        self.assertNotIn(self.data['access_token'], repr(lease))
        self.assertNotIn(self.data['access_token'], repr(self.response()))

    def test_rounding_and_scope_order(self):
        self.data['scope'] = 'api.model.request api.model.read'
        self.start += timedelta(microseconds=500000)
        self.now = self.start
        self.parse()

    def test_missing_extra_or_duplicate_scopes_rejected(self):
        for scopes in ('', 'api.model.read', 'api.model.read api.model.request admin',
                       'api.model.read api.model.request api.model.read',
                       'api.model.read\tapi.model.request', 'api.model.read api.model.request '):
            with self.subTest(scopes=scopes):
                self.data['scope'] = scopes
                with self.assertRaises(ProviderCredentialLeaseError):
                    self.parse()

    def test_malformed_fields_rejected(self):
        original = self.data.copy()
        for change in ({'token_type': 'Basic'}, {'issued_token_type': 'refresh_token'},
                       {'expires_in': True}, {'expires_in': 0}, {'expires_in': 3601},
                       {'expires_at': 1.5}, {'expires_at': True}, {'expires_at': 10**100},
                       {'expires_at': int(self.now.timestamp()) - 1},
                       {'expires_at': int(self.now.timestamp()) + 700},
                       {'expires_at': int(self.now.timestamp()) + 500},
                       {'access_token': 'short'}, {'access_token': 'bad-secret\nheader'},
                       {'refresh_token': 'unexpected-secret'}, {'scope': None}):
            self.data = original | change
            with self.subTest(fields=list(change)):
                with self.assertRaises(ProviderCredentialLeaseError):
                    self.parse()
        self.data = original
        del self.data['scope']
        with self.assertRaises(ProviderCredentialLeaseError):
            self.parse()

    def test_json_boundary_and_error_redaction(self):
        for raw in (b'\xff', b'{"secret": invalid}', b'[]', b'x'*65537,
                    b'{"access_token":"fake-response-secret-only","access_token":"duplicate"}'):
            with self.assertRaises(ProviderCredentialLeaseError) as caught:
                self.parse(ExchangeResponse(raw, self.now + timedelta(hours=1)))
            rendered = ''.join(traceback.format_exception(caught.exception))
            self.assertNotIn('fake-response-secret-only', rendered)
            self.assertNotIn('duplicate exchange field', rendered)

    def test_subject_expiry_and_clock_bounds(self):
        with self.assertRaises(ProviderCredentialLeaseError):
            self.parse(replace(self.response(), subject_expires_at=self.now + timedelta(seconds=599)))
        self.now -= timedelta(seconds=1)
        with self.assertRaises(ProviderCredentialLeaseError):
            self.parse()

    def test_response_failure_categories_and_redaction(self):
        original = self.data.copy()
        cases = (
            ({'unexpected-secret-field': 'secret-value'}, 'response_fields'),
            ({'token_type': 'secret-value'}, 'token_type'),
            ({'issued_token_type': 'secret-value'}, 'token_type'),
            ({'access_token': 'secret\nvalue'}, 'token_encoding'),
            ({'scope': None}, 'scope_format'),
            ({'scope': 'secret-value'}, 'scope_mismatch'),
            ({'expires_in': True}, 'lifetime_format'),
            ({'expires_at': 10**100}, 'lifetime_format'),
            ({'expires_at': int(self.now.timestamp()) + 700}, 'issuance_clock'),
        )
        for change, reason in cases:
            with self.subTest(reason=reason, fields=list(change)):
                self.data = original | change
                with self.assertRaises(IdentityFailure) as caught:
                    self.parse()
                self.assertEqual(failure_receipt(caught.exception),
                    {'failure_stage': 'exchange_response', 'failure_reason': reason})
                rendered = ''.join(traceback.format_exception(caught.exception))
                self.assertNotIn('secret-value', rendered)
                self.assertNotIn('unexpected-secret-field', rendered)
                self.assertNotIn(original['access_token'], rendered)

    def test_boundary_json_clock_and_expiry_categories(self):
        cases = (
            (ExchangeResponse(b'x'*65537, self.now), {}, 'response_boundary'),
            (ExchangeResponse(b'{"secret-value": invalid}', self.now), {}, 'response_json'),
            (ExchangeResponse(b'{"x":1,"x":2}', self.now), {}, 'response_json'),
            (ExchangeResponse(b'[]', self.now), {}, 'response_fields'),
            (replace(self.response(), subject_expires_at=self.now), {}, 'subject_expiry'),
            (self.response(), {'scopes': ('secret value',)}, 'expected_scopes'),
        )
        for response, kwargs, reason in cases:
            with self.subTest(reason=reason):
                with self.assertRaises(IdentityFailure) as caught:
                    self.parse(response, **kwargs)
                self.assertEqual(failure_receipt(caught.exception)['failure_reason'], reason)
        self.now = self.start - timedelta(seconds=1)
        with self.assertRaises(IdentityFailure) as caught:
            self.parse()
        self.assertEqual(caught.exception.reason, 'response_clock')
        self.now = self.start + timedelta(seconds=600)
        with self.assertRaises(IdentityFailure) as caught:
            self.parse()
        self.assertEqual(caught.exception.reason, 'expired')

    def test_scope_diagnostics_reject_every_mismatch_without_values(self):
        expected = ('api.model.request',)
        for value, reason in (
            ('api.model.read api.model.request', 'scope_read_extra'),
            ('api.model.request secret-extra', 'scope_extra'),
            ('api.model.read', 'scope_mismatch'),
            ('', 'scope_missing'),
            ('api.model.request api.model.request', 'scope_mismatch'),
        ):
            with self.subTest(reason=reason, value=value):
                self.data['scope'] = value
                with self.assertRaises(IdentityFailure) as caught:
                    self.parse(scopes=expected)
                self.assertEqual(failure_receipt(caught.exception),
                    {'failure_stage': 'exchange_response', 'failure_reason': reason})
                self.assertNotIn('secret-extra', ''.join(traceback.format_exception(caught.exception)))

    async def test_disabled_and_paused_never_exchange(self):
        ledger = self.ledger()
        for enabled in (False, True):
            with self.assertRaises(ProviderCredentialLeaseError):
                await self.source(ledger, enabled).issue(target=self.target)
        self.assertEqual(self.calls, 0)

    async def test_full_path_caches_without_persisting_token(self):
        ledger = self.ledger(); ledger.pause(False)
        source = self.source(ledger)
        first = await source.issue(target=self.target)
        self.assertIs(await source.issue(target=self.target), first)
        self.assertEqual(self.calls, 1)
        self.assertNotIn(self.data['access_token'].encode(), self.path.read_bytes())

    async def test_scope_failure_survives_restart_without_retry(self):
        ledger = self.ledger(); ledger.pause(False)
        self.data['scope'] += ' admin'
        with self.assertRaises(IdentityFailure) as caught:
            await self.source(ledger).issue(target=self.target)
        self.assertEqual(failure_receipt(caught.exception),
            {'failure_stage': 'exchange_response', 'failure_reason': 'scope_extra'})
        self.data['scope'] = ' '.join(self.scopes)
        with self.assertRaises(ProviderCredentialLeaseError):
            await self.source(self.ledger()).issue(target=self.target)
        self.assertEqual(self.calls, 1)

    async def test_automatic_renewal_consumes_next_approved_slot(self):
        ledger = self.ledger(); ledger.pause(False)
        source = self.source(ledger)
        await source.issue(target=self.target)
        self.now += timedelta(seconds=390)
        self.data['expires_at'] = int(self.now.timestamp()) + 600
        await source.issue(target=self.target)
        self.now += timedelta(seconds=390)
        self.data['expires_at'] = int(self.now.timestamp()) + 600
        with self.assertRaises(ProviderCredentialLeaseError):
            await source.issue(target=self.target)
        self.assertEqual(self.calls, 2)

    async def test_adapter_lifetime_bound_not_artificially_shortened(self):
        ledger = self.ledger(); ledger.pause(False)
        self.data.update(expires_in=3600, expires_at=int(self.now.timestamp()) + 3600)
        with self.assertRaises(ProviderCredentialLeaseError):
            await self.source(ledger).issue(target=self.target)
        with self.assertRaises(ProviderCredentialLeaseError):
            await self.source(self.ledger()).issue(target=self.target)
        self.assertEqual(self.calls, 1)


if __name__ == '__main__':
    unittest.main()
