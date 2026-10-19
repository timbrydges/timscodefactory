import asyncio
from unittest import TestCase
from unittest.mock import patch

from factory_runtime.provider_http_transport import DirectOpenAITransport
from factory_runtime.openai_provider import OpenAIProviderDisabledError, OpenAIProviderProtocolError


class TransportTests(TestCase):
    def setUp(self):
        self.args = dict(endpoint='https://api.openai.com/v1/responses',
            headers={'Authorization': 'Bearer fake-offline-key',
                     'Content-Type': 'application/json', 'Accept': 'application/json'},
            body=b'{}', timeout_seconds=10)

    def call(self, **options):
        return asyncio.run(DirectOpenAITransport(**options).post_json(**self.args))

    @patch('factory_runtime.provider_http_transport.http.client.HTTPSConnection')
    def test_disabled_and_wrong_destination_never_connect(self, connect):
        with self.assertRaises(OpenAIProviderDisabledError):
            self.call()
        self.args['endpoint'] = 'https://example.com/v1/responses'
        with self.assertRaises(OpenAIProviderProtocolError):
            self.call(enabled=True)
        connect.assert_not_called()

    @patch('factory_runtime.provider_http_transport.http.client.HTTPSConnection')
    def test_success_is_single_bounded_request_and_closes(self, connect):
        response = connect.return_value.getresponse.return_value
        response.status, response.read.return_value = 200, b'{}'
        self.assertEqual(self.call(enabled=True).body, b'{}')
        connect.return_value.request.assert_called_once()
        response.read.assert_called_once_with(262145)
        connect.return_value.close.assert_called_once()

    @patch('factory_runtime.provider_http_transport.http.client.HTTPSConnection')
    def test_redirect_not_followed_or_read(self, connect):
        response = connect.return_value.getresponse.return_value
        response.status = 302
        self.assertEqual(self.call(enabled=True).status_code, 302)
        response.read.assert_not_called()
        connect.assert_called_once()

    @patch('factory_runtime.provider_http_transport.http.client.HTTPSConnection')
    def test_timeout_not_retried_or_leaked(self, connect):
        connect.return_value.request.side_effect = TimeoutError('secret diagnostic')
        with self.assertRaises(OpenAIProviderProtocolError) as error:
            self.call(enabled=True)
        self.assertNotIn('secret', str(error.exception))
        connect.return_value.request.assert_called_once()
        connect.return_value.close.assert_called_once()

    @patch('factory_runtime.provider_http_transport.http.client.HTTPSConnection')
    def test_response_limit_stops(self, connect):
        response = connect.return_value.getresponse.return_value
        response.status, response.read.return_value = 200, b'x'*4097
        with self.assertRaises(OpenAIProviderProtocolError):
            self.call(enabled=True, max_response_bytes=4096)
        connect.return_value.request.assert_called_once()
