"""One direct HTTPS request, no proxy, redirect, retry or implicit activation."""
import asyncio
import http.client
import ssl
import json
import os
import sys
from pathlib import Path

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
        # Isolate blocking DNS/TLS/socket IO in a killable child. Credentials go
        # through a private pipe, never argv, environment, or a disk file.
        payload = json.dumps({'headers': dict(headers), 'body': body.decode('utf-8'),
            'timeout': timeout_seconds, 'limit': self.max_response_bytes}).encode()
        child = None
        try:
            async with asyncio.timeout(timeout_seconds):
                spawn = asyncio.create_task(asyncio.create_subprocess_exec(sys.executable, '-I', '-c',
                    'import sys; sys.path.insert(0, sys.argv[1]); '
                    'from factory_runtime.provider_http_transport import _worker; _worker()',
                    str(Path(__file__).resolve().parents[1]),
                    stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.DEVNULL,
                    env={k: os.environ[k] for k in ('SystemRoot', 'WINDIR') if k in os.environ}))
                try:
                    child = await asyncio.shield(spawn)
                except asyncio.CancelledError:
                    child = await spawn
                    raise
                stdout, _ = await child.communicate(payload)
                if child.returncode != 0 or len(stdout) > self.max_response_bytes * 6 + 128:
                    raise ValueError('invalid child result')
                result = json.loads(stdout)
                raw = result['body'].encode('utf-8')
                if type(result['status']) is not int or len(raw) > self.max_response_bytes:
                    raise ValueError('invalid child response')
                return ProviderHTTPResponse(result['status'], raw)
        except asyncio.CancelledError:
            raise
        except Exception:
            raise OpenAIProviderProtocolError('provider transport failed; attempt consumed') from None
        finally:
            payload = b''
            if child is not None and child.returncode is None:
                try:
                    child.kill()
                except ProcessLookupError:
                    pass
                await child.wait()

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


def _worker():
    """Private subprocess endpoint; no retry and no diagnostic output."""
    try:
        raw = sys.stdin.buffer.read(2 * 1048576)
        request = json.loads(raw)
        response = DirectOpenAITransport(max_response_bytes=request['limit'])._post(
            request['headers'], request['body'].encode('utf-8'), request['timeout'])
        sys.stdout.write(json.dumps({'status': response.status_code,
                                    'body': response.body.decode('utf-8')}))
    except Exception:
        sys.exit(1)
