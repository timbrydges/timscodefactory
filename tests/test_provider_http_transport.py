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
        transport = DirectOpenAITransport(**options)
        if options.get('enabled') and self.args['endpoint'] == 'https://api.openai.com/v1/responses':
            return transport._post(dict(self.args['headers']), self.args['body'], 10)
        return asyncio.run(transport.post_json(**self.args))

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
        self.assertEqual(error.exception.failure_code, 'timeout')
        connect.return_value.request.assert_called_once()
        connect.return_value.close.assert_called_once()

    @patch('factory_runtime.provider_http_transport.http.client.HTTPSConnection')
    def test_connection_failure_is_distinct_and_does_not_leak(self, connect):
        connect.return_value.request.side_effect = OSError('private connection details')
        with self.assertRaises(OpenAIProviderProtocolError) as error:
            self.call(enabled=True)
        self.assertEqual(error.exception.failure_code, 'transport_failure')
        self.assertNotIn('private', str(error.exception))
        connect.return_value.request.assert_called_once()

    @patch('factory_runtime.provider_http_transport.http.client.HTTPSConnection')
    def test_response_limit_stops(self, connect):
        response = connect.return_value.getresponse.return_value
        response.status, response.read.return_value = 200, b'x'*4097
        with self.assertRaises(OpenAIProviderProtocolError) as error:
            self.call(enabled=True, max_response_bytes=4096)
        self.assertEqual(error.exception.failure_code, 'response_byte_limit')
        connect.return_value.request.assert_called_once()
