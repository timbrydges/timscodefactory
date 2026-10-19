import asyncio
import json
import sys
from unittest import IsolatedAsyncioTestCase
from unittest.mock import AsyncMock, Mock, patch
from factory_runtime.provider_http_transport import DirectOpenAITransport
from factory_runtime.openai_provider import OpenAIProviderProtocolError


class CancellationTests(IsolatedAsyncioTestCase):
    def setUp(self):
        self.args = dict(endpoint='https://api.openai.com/v1/responses',
            headers={'Authorization': 'Bearer offline-fake-key',
                     'Content-Type': 'application/json', 'Accept': 'application/json'},
            body=b'{}', timeout_seconds=1)

    async def test_timeout_kills_and_reaps_once_without_retry(self):
        child = Mock(returncode=None)
        async def blocked(payload):
            await asyncio.Event().wait()
        child.communicate = blocked
        child.wait = AsyncMock()
        with patch('asyncio.create_subprocess_exec', AsyncMock(return_value=child)) as spawn:
            with self.assertRaises(OpenAIProviderProtocolError) as error:
                await DirectOpenAITransport(enabled=True).post_json(**self.args)
            self.assertEqual(error.exception.failure_code, 'timeout')
            spawn.assert_awaited_once()
            self.assertNotIn('offline-fake-key', repr(spawn.call_args))
        child.kill.assert_called_once()
        child.wait.assert_awaited_once()

    async def test_caller_cancellation_reaps_child(self):
        entered = asyncio.Event()
        child = Mock(returncode=None)
        async def blocked(payload):
            entered.set()
            await asyncio.Event().wait()
        child.communicate = blocked
        child.wait = AsyncMock()
        with patch('asyncio.create_subprocess_exec', AsyncMock(return_value=child)):
            task = asyncio.create_task(DirectOpenAITransport(enabled=True).post_json(**self.args))
            await entered.wait()
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task
        child.kill.assert_called_once()
        child.wait.assert_awaited_once()

    async def test_child_failure_codes_are_preserved_but_untrusted_text_is_not(self):
        for code, expected in [('timeout', 'timeout'), ('transport_failure', 'transport_failure'),
                               ('private secret', 'protocol_failure')]:
            child = Mock(returncode=0)
            child.communicate = AsyncMock(return_value=(json.dumps({'error_code': code}).encode(), None))
            with patch('asyncio.create_subprocess_exec', AsyncMock(return_value=child)) as spawn:
                with self.assertRaises(OpenAIProviderProtocolError) as error:
                    await DirectOpenAITransport(enabled=True).post_json(**self.args)
                self.assertEqual(error.exception.failure_code, expected)
                self.assertNotIn('secret', str(error.exception))
                spawn.assert_awaited_once()

    async def test_success_uses_pipe_and_does_not_kill_completed_child(self):
        child = Mock(returncode=0)
        child.communicate = AsyncMock(return_value=(b'{"status":200,"body":"{}"}', None))
        with patch('asyncio.create_subprocess_exec', AsyncMock(return_value=child)):
            result = await DirectOpenAITransport(enabled=True).post_json(**self.args)
        self.assertEqual(result.body, b'{}')
        payload = json.loads(child.communicate.call_args.args[0])
        self.assertEqual(payload['headers'], self.args['headers'])
        child.kill.assert_not_called()

    async def test_real_offline_child_is_reaped_after_deadline(self):
        original = asyncio.create_subprocess_exec
        children = []
        async def offline_child(*args, **kwargs):
            child = await original(sys.executable, '-I', '-c',
                'import time; time.sleep(30)', **kwargs)
            children.append(child)
            return child
        with patch('asyncio.create_subprocess_exec', offline_child):
            with self.assertRaises(OpenAIProviderProtocolError):
                await DirectOpenAITransport(enabled=True).post_json(**self.args)
        self.assertEqual(len(children), 1)
        self.assertIsNotNone(children[0].returncode)
