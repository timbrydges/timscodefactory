import asyncio
import base64
from dataclasses import replace
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import tempfile
from unittest import IsolatedAsyncioTestCase
from unittest.mock import AsyncMock, Mock, patch

from factory_runtime.credential_issuance import CredentialIssuanceLedger, IssuanceAuthorization
from factory_runtime.workload_identity_transport import JWTTokenExchange
from factory_runtime.github_subject_identity import (
    DirectGitHubIdentityTransport, GitHubIdentityPolicy, GitHubSubjectSource, request_target)
from factory_runtime.openai_provider import OpenAIProviderDisabledError, ProviderHTTPResponse
from factory_runtime.provider_broker_service import ResolvedProviderTarget
from factory_runtime.provider_credentials import ProviderCredentialLeaseError


class GitHubSubjectTests(IsolatedAsyncioTestCase):
    def setUp(self):
        self.now = datetime(2026, 10, 20, tzinfo=timezone.utc)
        self.auth = IssuanceAuthorization('sha256:'+'a'*64, 'fake-idp', 'fake-sa',
            ResolvedProviderTarget('openai', 'fake-model', 'v1'),
            self.now, self.now+timedelta(hours=1), 2, ('api.model.request',), 90)
        self.policy = GitHubIdentityPolicy(
            'https://pipelines.actions.githubusercontent.com', 'https://api.openai.com/v1',
            'owner/control', '123', 'owner/control/.github/workflows/runner.yml@refs/heads/main')
        self.url = self.policy.request_origin + '/job/oidc?api-version=2.0'
        self.environment = Mock(side_effect={
            'ACTIONS_ID_TOKEN_REQUEST_URL': self.url,
            'ACTIONS_ID_TOKEN_REQUEST_TOKEN': 'fake-job-request-bearer'
        }.get)
        self.transport = Mock(request=AsyncMock(return_value=self.response()))

    def response(self, **changes):
        claims = self.policy.claims() | dict(iat=int(self.now.timestamp()),
                                             exp=int(self.now.timestamp())+300)
        claims.update(changes)
        payload = base64.urlsafe_b64encode(json.dumps(claims).encode()).rstrip(b'=').decode()
        return ProviderHTTPResponse(200, json.dumps({'value':'header.'+payload+'.signature'}).encode())

    def source(self, **kwargs):
        return GitHubSubjectSource(authorization=self.auth, policy=self.policy,
            environment=self.environment, clock=lambda:self.now,
            transport=self.transport, **kwargs)

    async def test_failure_stages_are_safe_and_single_call(self):
        from factory_runtime.identity_diagnostics import IdentityFailure, failure_receipt
        cases = [
            (ProviderHTTPResponse(403, b'secret-token'), 'github_http'),
            (ProviderHTTPResponse(200, b'secret-token'), 'github_payload'),
            (self.response(repository='other/private'), 'github_claims'),
            (self.response(exp=int(self.now.timestamp())+100), 'github_lifetime'),
        ]
        for response, stage in cases:
            with self.subTest(stage=stage):
                self.transport.request.reset_mock()
                self.transport.request.return_value = response
                with self.assertRaises(IdentityFailure) as caught:
                    await self.source(enabled=True)(self.auth)
                self.assertEqual(failure_receipt(caught.exception)['failure_stage'], stage)
                self.assertNotIn('secret-token', str(caught.exception))
                self.transport.request.assert_awaited_once()

    async def test_default_never_reads_environment_or_sends(self):
        with self.assertRaises(ProviderCredentialLeaseError):
            await self.source()(self.auth)
        self.environment.assert_not_called()
        self.transport.request.assert_not_called()

    async def test_one_request_checks_claims_and_returns_absolute_expiry(self):
        result = await self.source(enabled=True)(self.auth)
        self.assertEqual(result.expires_at, self.now+timedelta(seconds=300))
        self.transport.request.assert_awaited_once_with(
            url=self.url, bearer='fake-job-request-bearer', policy=self.policy)
        self.assertNotIn(result.token, repr(result))

    async def test_wrong_or_expired_authorization_stops_before_environment(self):
        for auth in (replace(self.auth, service_account_id='other'),
                     replace(self.auth, expires_at=self.now)):
            with self.assertRaises(ProviderCredentialLeaseError):
                await self.source(enabled=True)(auth)
        self.environment.assert_not_called()

    async def test_foreign_origin_stops_before_bearer_read(self):
        self.environment.side_effect = lambda key: 'https://attacker.invalid/token'
        with self.assertRaises(ProviderCredentialLeaseError):
            await self.source(enabled=True)(self.auth)
        self.environment.assert_called_once_with('ACTIONS_ID_TOKEN_REQUEST_URL')
        self.transport.request.assert_not_called()

    async def test_claim_mismatch_and_bad_times_never_return_identity(self):
        cases = [{key:'wrong'} for key in self.policy.claims()]
        cases += [{'iat':True}, {'exp':True}, {'iat':int(self.now.timestamp())-2},
                  {'iat':int(self.now.timestamp())+1}, {'exp':int(self.now.timestamp())+210},
                  {'exp':int(self.now.timestamp())+901}]
        for changes in cases:
            with self.subTest(changes=changes):
                self.transport.request.return_value = self.response(**changes)
                with self.assertRaises(ProviderCredentialLeaseError):
                    await self.source(enabled=True)(self.auth)

    async def test_malformed_and_non_success_responses_are_sanitized(self):
        for response in (ProviderHTTPResponse(302, b'private'),
                         ProviderHTTPResponse(200, b'x'*65537),
                         ProviderHTTPResponse(200, b'{"value":"bad","value":"other"}'),
                         ProviderHTTPResponse(200, b'{"value":"a.b.c"}')):
            self.transport.request.return_value = response
            with self.assertRaises(ProviderCredentialLeaseError) as caught:
                await self.source(enabled=True)(self.auth)
            self.assertNotIn('private', str(caught.exception))

    async def test_failure_and_cancellation_do_not_retry(self):
        for error in (TimeoutError('private'), RuntimeError('private'), asyncio.CancelledError()):
            self.transport.request.reset_mock()
            self.transport.request.side_effect = error
            with self.assertRaises((ProviderCredentialLeaseError, asyncio.CancelledError)):
                await self.source(enabled=True)(self.auth)
            self.transport.request.assert_awaited_once()

    async def test_durable_binding_renews_or_blocks_failed_renewal_replay(self):
        self.transport.request.side_effect = lambda **kwargs:self.response()
        provider = Mock(post_json=AsyncMock())
        async def exchange_response(**kwargs):
            return ProviderHTTPResponse(200, json.dumps(dict(
                access_token='fake-exchanged-access-token', token_type='Bearer',
                issued_token_type='urn:ietf:params:oauth:token-type:access_token',
                expires_in=300, expires_at=int(self.now.timestamp())+300,
                scope='api.model.request')).encode())
        provider.post_json.side_effect = exchange_response
        for failure in (False, True):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as directory:
                self.now = self.auth.starts_at
                self.transport.request.reset_mock()
                self.transport.request.side_effect = lambda **kwargs:self.response()
                provider.post_json.reset_mock()
                ledger = CredentialIssuanceLedger(Path(directory)/'issuance.db', self.auth,
                                                 operator_authorized=True)
                ledger.pause(False)
                exchange = JWTTokenExchange(authorization=self.auth, subject_source=self.source(enabled=True),
                                            clock=lambda:self.now, enabled=True, transport=provider)
                credential = exchange.binding(ledger).compose(clock=lambda:self.now)
                first = await credential.issue(target=self.auth.target)
                self.now += timedelta(seconds=180)
                if failure:
                    self.transport.request.side_effect = TimeoutError()
                    with self.assertRaises(ProviderCredentialLeaseError):
                        await credential.issue(target=self.auth.target)
                else:
                    second = await credential.issue(target=self.auth.target)
                    self.assertGreater(second.expires_at, first.expires_at)
                    self.now += timedelta(seconds=180)
                with self.assertRaises(ProviderCredentialLeaseError):
                    await credential.issue(target=self.auth.target)
                self.assertEqual(self.transport.request.await_count, 2)
                self.assertEqual(provider.post_json.await_count, 1 if failure else 2)
                self.assertEqual(first.expires_at, self.auth.starts_at+timedelta(seconds=300))
                self.assertNotIn(b'fake-exchanged-access-token', ledger.path.read_bytes())

    def test_request_target_has_exact_origin_and_one_encoded_audience(self):
        host, path = request_target(self.url, self.policy.request_origin, self.policy.audience)
        self.assertEqual(host, 'pipelines.actions.githubusercontent.com')
        self.assertEqual(path, '/job/oidc?api-version=2.0&audience=https%3A%2F%2Fapi.openai.com%2Fv1')
        for url in ('http://pipelines.actions.githubusercontent.com/token',
                    self.url+'&audience=other', self.url+'&%61udience=other',
                    self.url+'#fragment', self.url+'\r\nX:bad',
                    self.url.replace('pipelines.', 'other.'),
                    self.url.replace('pipelines.', 'user@pipelines.'),
                    self.url.replace('.com/', '.com:443/')):
            with self.subTest(url=url), self.assertRaises(ValueError):
                request_target(url, self.policy.request_origin, self.policy.audience)

    async def test_transport_disabled_and_invalid_bearer_never_spawn(self):
        with patch.object(DirectGitHubIdentityTransport, '_run_request', new_callable=AsyncMock) as run:
            with self.assertRaises(OpenAIProviderDisabledError):
                await DirectGitHubIdentityTransport().request(url=self.url, bearer='fake', policy=self.policy)
            with self.assertRaises(ValueError):
                await DirectGitHubIdentityTransport(enabled=True).request(
                    url=self.url, bearer='bad\r\nheader-injection', policy=self.policy)
            run.assert_not_called()

    async def test_transport_uses_private_child_operation(self):
        with patch.object(DirectGitHubIdentityTransport, '_run_request', new_callable=AsyncMock) as run:
            await DirectGitHubIdentityTransport(enabled=True).request(
                url=self.url, bearer='fake-job-request-bearer', policy=self.policy)
            run.assert_awaited_once()
            self.assertEqual(run.call_args.kwargs, {'kind':'github-subject'})
            self.assertEqual(run.call_args.args[2], 10)
            self.assertNotIn('fake-job-request-bearer', run.call_args.args[1].decode())

    @patch('factory_runtime.provider_http_transport.http.client.HTTPSConnection')
    async def test_socket_uses_get_and_does_not_follow_redirect(self, connect):
        connect.return_value.getresponse.return_value.status = 302
        body = json.dumps(dict(url=self.url, origin=self.policy.request_origin,
                               audience=self.policy.audience)).encode()
        result = DirectGitHubIdentityTransport()._post(
            {'Authorization':'Bearer fake-job-request-bearer'}, body, 10, kind='github-subject')
        self.assertEqual(result.status_code, 302)
        self.assertEqual(result.body, b'')
        self.assertEqual(connect.call_args.args, ('pipelines.actions.githubusercontent.com',))
        self.assertEqual(connect.return_value.request.call_args.args[0], 'GET')
        connect.return_value.getresponse.return_value.read.assert_not_called()
        connect.return_value.close.assert_called_once()
