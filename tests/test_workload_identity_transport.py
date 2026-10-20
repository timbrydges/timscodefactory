import asyncio
from dataclasses import replace
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import AsyncMock, patch

from factory_runtime.credential_issuance import CredentialIssuanceLedger, IssuanceAuthorization
from factory_runtime.openai_provider import ProviderHTTPResponse, OpenAIProviderDisabledError, OpenAIProviderProtocolError
from factory_runtime.provider_broker_service import ResolvedProviderTarget
from factory_runtime.provider_credentials import ProviderCredentialLeaseError
from factory_runtime.workload_identity_transport import (
    DirectTokenExchangeTransport, JWTTokenExchange, TrustedSubjectIdentity)


class IdentityTransportTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.now = datetime(2026, 10, 20, tzinfo=timezone.utc)
        self.target = ResolvedProviderTarget('openai', 'fake-model', 'v1')
        self.auth = IssuanceAuthorization('sha256:'+'a'*64, 'idp-test', 'sa-test', self.target,
            self.now, self.now+timedelta(hours=1), 2, ('api.model.request',), 1)
        self.subject = TrustedSubjectIdentity('fakeheader.fakepayload.fakesignature', self.now+timedelta(seconds=600))
        self.source = AsyncMock(return_value=self.subject)
        self.transport = AsyncMock()
        self.body = json.dumps(dict(access_token='fake-access-token-only', token_type='Bearer',
            issued_token_type='urn:ietf:params:oauth:token-type:access_token',
            expires_at=int(self.now.timestamp())+600, expires_in=600, scope='api.model.request')).encode()
        self.transport.post_json.return_value = ProviderHTTPResponse(200, self.body)

    def exchange(self, enabled=True):
        return JWTTokenExchange(authorization=self.auth, subject_source=self.source,
            clock=lambda: self.now, enabled=enabled, transport=self.transport)

    def request(self):
        return dict(endpoint='https://auth.openai.com/oauth/token', timeout_seconds=20,
            headers={'Content-Type': 'application/json', 'Accept': 'application/json'},
            body=json.dumps(dict(grant_type='urn:ietf:params:oauth:grant-type:token-exchange',
                subject_token_type='urn:ietf:params:oauth:token-type:jwt',
                subject_token=self.subject.token, identity_provider_id='idp-test', service_account_id='sa-test'),
                separators=(',', ':')).encode())

    async def test_disabled_never_reads_subject_or_sends(self):
        with self.assertRaises(ProviderCredentialLeaseError):
            await self.exchange(False)(self.auth)
        self.source.assert_not_called(); self.transport.post_json.assert_not_called()

    async def test_changed_mapping_rejected_before_subject_access(self):
        with self.assertRaises(ProviderCredentialLeaseError):
            await self.exchange()(replace(self.auth, service_account_id='different'))
        self.source.assert_not_called()

    async def test_expired_authorization_never_reads_subject(self):
        self.now = self.auth.expires_at
        with self.assertRaises(ProviderCredentialLeaseError):
            await self.exchange()(self.auth)
        self.source.assert_not_called()

    async def test_one_exact_exchange_and_no_scope_grant_in_request(self):
        result = await self.exchange()(self.auth)
        self.assertEqual(result.body, self.body)
        self.assertEqual(result.subject_expires_at, self.subject.expires_at)
        self.source.assert_awaited_once_with(self.auth)
        self.transport.post_json.assert_awaited_once()
        request = self.transport.post_json.call_args.kwargs
        self.assertEqual(request, self.request())
        self.assertNotIn(self.subject.token, repr(self.subject))

    async def test_subject_expiry_and_shape_stop_before_transport(self):
        for subject in (None, replace(self.subject, token='bad'),
                        replace(self.subject, expires_at=self.now+timedelta(seconds=210)),
                        replace(self.subject, expires_at=self.now.replace(tzinfo=None))):
            self.source.return_value = subject
            with self.assertRaises(ProviderCredentialLeaseError):
                await self.exchange()(self.auth)
        self.transport.post_json.assert_not_called()

    async def test_subject_failure_and_cancellation_not_retried(self):
        for error in (RuntimeError('private detail'), asyncio.CancelledError()):
            self.source.reset_mock(); self.source.side_effect = error
            with self.assertRaises((ProviderCredentialLeaseError, asyncio.CancelledError)) as caught:
                await self.exchange()(self.auth)
            self.assertNotIn('private', str(caught.exception))
            self.source.assert_awaited_once()
        self.transport.post_json.assert_not_called()

    async def test_non_success_never_returns_error_body(self):
        for status in (302, 401, 429, 500):
            self.transport.reset_mock()
            self.transport.post_json.return_value = ProviderHTTPResponse(status, b'private-error-body')
            with self.assertRaises(ProviderCredentialLeaseError) as caught:
                await self.exchange()(self.auth)
            self.assertNotIn('private', str(caught.exception))
            self.transport.post_json.assert_awaited_once()

    async def test_durable_full_path_blocks_second_exchange_after_failure(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder)/'issuance.db'
            ledger = CredentialIssuanceLedger(path, self.auth, operator_authorized=True)
            ledger.pause(False)
            exchange = self.exchange()
            self.transport.post_json.side_effect = TimeoutError('private')
            with self.assertRaises(ProviderCredentialLeaseError):
                await exchange.binding(ledger).compose(clock=lambda: self.now).issue(target=self.target)
            reopened = CredentialIssuanceLedger(path, self.auth, operator_authorized=True)
            with self.assertRaises(ProviderCredentialLeaseError):
                await self.exchange().binding(reopened).compose(clock=lambda: self.now).issue(target=self.target)
            self.source.assert_awaited_once(); self.transport.post_json.assert_awaited_once()
            self.assertNotIn(self.subject.token.encode(), path.read_bytes())

    async def test_transport_activation_and_endpoint_checks(self):
        with patch.object(DirectTokenExchangeTransport, '_run_request', new_callable=AsyncMock) as send:
            with self.assertRaises(OpenAIProviderDisabledError):
                await DirectTokenExchangeTransport().post_json(**self.request())
            for change in ({'endpoint': 'https://example.com/oauth/token'},
                           {'headers': {'Authorization': 'Bearer fake'}}, {'timeout_seconds': 31},
                           {'body': b'x'*65537}, {'body': b'{"subject_token":"a","subject_token":"b"}'}):
                with self.assertRaises(OpenAIProviderProtocolError):
                    await DirectTokenExchangeTransport(enabled=True).post_json(**(self.request() | change))
            send.assert_not_called()

    async def test_transport_selects_only_token_operation(self):
        with patch.object(DirectTokenExchangeTransport, '_run_request', new_callable=AsyncMock) as send:
            await DirectTokenExchangeTransport(enabled=True).post_json(**self.request())
            send.assert_awaited_once()
            self.assertEqual(send.call_args.kwargs, {'kind': 'token-exchange'})

    @patch('factory_runtime.provider_http_transport.http.client.HTTPSConnection')
    async def test_socket_route_fixed_and_redirect_not_followed(self, connect):
        connect.return_value.getresponse.return_value.status = 302
        result = DirectTokenExchangeTransport()._post({}, b'{}', 20, kind='token-exchange')
        self.assertEqual(connect.call_args.args, ('auth.openai.com',))
        self.assertEqual(connect.return_value.request.call_args.args, ('POST', '/oauth/token'))
        connect.return_value.getresponse.return_value.read.assert_not_called()
        connect.return_value.close.assert_called_once()
        self.assertEqual(result.body, b'')


if __name__ == '__main__':
    unittest.main()
