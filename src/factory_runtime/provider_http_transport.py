"""One direct HTTPS request, no proxy, redirect, retry or implicit activation."""
import asyncio
import http.client
import ssl

from .openai_provider import ProviderHTTPResponse, OpenAIProviderDisabledError, OpenAIProviderProtocolError


class DirectOpenAITransport:
    def __init__(self, *, enabled=False, max_request_bytes=42020, max_response_bytes=262144):
        if type(enabled) is not bool:
            raise ValueError('explicit boolean activation required')
        for value in (max_request_bytes, max_response_bytes):
            if type(value) is not int or not 4096 <= value <= 1048576:
                raise ValueError('bounded positive byte limits required')
        self.enabled = enabled
        self.max_request_bytes, self.max_response_bytes = max_request_bytes, max_response_bytes

    async def post_json(self, *, endpoint, headers, body, timeout_seconds):
        if not self.enabled:
            raise OpenAIProviderDisabledError('HTTP transport disabled')
        if (endpoint != 'https://api.openai.com/v1/responses'
                or type(body) is not bytes or len(body) > self.max_request_bytes
                or type(timeout_seconds) is not int or not 1 <= timeout_seconds <= 180
                or type(headers) is not dict
                or set(headers) != {'Authorization', 'Content-Type', 'Accept'}
                or headers.get('Content-Type') != 'application/json'
                or headers.get('Accept') != 'application/json'
                or not isinstance(headers.get('Authorization'), str)
                or not headers['Authorization'].startswith('Bearer ')
                or any(not isinstance(v, str) or any(ord(c) < 32 or ord(c) > 126 for c in v)
                       for v in headers.values())):
            raise OpenAIProviderProtocolError('invalid bounded transport request')
        # Copy before yielding; the caller drops its own credential references.
        return await asyncio.to_thread(self._post, dict(headers), body, timeout_seconds)

    def _post(self, headers, body, timeout):
        connection = None
        try:
            connection = http.client.HTTPSConnection('api.openai.com', timeout=timeout,
                                                     context=ssl.create_default_context())
            connection.request('POST', '/v1/responses', body=body, headers=headers)
            response = connection.getresponse()
            # Never follow redirects, retry errors, or retain provider error bodies.
            if response.status != 200:
                return ProviderHTTPResponse(response.status, b'')
            raw = response.read(self.max_response_bytes + 1)
            if len(raw) > self.max_response_bytes:
                raise OpenAIProviderProtocolError('provider response exceeds byte limit')
            return ProviderHTTPResponse(response.status, raw)
        except Exception:
            raise OpenAIProviderProtocolError('provider transport failed; attempt consumed') from None
        finally:
            headers.clear()
            if connection is not None:
                connection.close()
