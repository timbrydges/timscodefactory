import unittest
from pathlib import Path
from unittest.mock import Mock, patch
from botocore.credentials import ReadOnlyCredentials
from factory_runtime.handoff003_transport import Handoff003Transport
from factory_runtime.handoff003_protocols import request_bytes
from factory_runtime.handoff003_packets import builder_packet, TASK
from factory_runtime.handoff003_receipts import sha
from factory_state.scope import canonical
from factory_state.model import StateError

ROOT = Path(__file__).resolve().parents[1]


class HandoffTransportTests(unittest.TestCase):
    def setUp(self):
        packet = builder_packet(ROOT)
        self.builder = canonical({'task_id': TASK, 'packet_digest': packet['packet_digest'],
            'files': packet['untrusted_files']})
        self.connection = Mock()
        self.response = self.connection.getresponse.return_value
        self.response.status = 200
        self.response.getheader.side_effect = lambda name, default: 'application/json' if name == 'Content-Type' else 'identity'
        self.response.read.return_value = b'{"bounded":"response"}'

    def context(self, role):
        return {'role': role, **({} if role == 'builder' else
            {'builder_response': self.builder, 'candidate_commit': 'a'*40})}

    def test_each_fixed_endpoint_sends_once_and_closes(self):
        for role in ('builder', 'inspector', 'qa'):
            with self.subTest(role=role), patch('factory_runtime.pilot002_transport.http.client.HTTPSConnection', return_value=self.connection) as connect:
                self.connection.reset_mock()
                context = self.context(role)
                transport = Handoff003Transport(ROOT, **context, enabled=True)
                raw = request_bytes(ROOT, **context)
                credential = ReadOnlyCredentials('A'*20, 'B'*40, 'C'*40) if role == 'inspector' else 'synthetic-not-a-key-1234'
                args = dict(request_bytes=raw, credential=credential, expected_request_digest=sha(raw))
                self.assertEqual(transport.send_once(**args), b'{"bounded":"response"}')
                with self.assertRaises(StateError): transport.send_once(**args)
                self.connection.request.assert_called_once()
                self.connection.close.assert_called_once()
                host, path = transport.routes[role]
                self.assertEqual(connect.call_args.args[:2], (host, 443))
                self.assertEqual(self.connection.request.call_args.args[:2], ('POST', path))
                if role == 'qa': self.assertIn('gemini-3.7-flash', path)

    def test_disabled_or_wrong_request_never_connects(self):
        raw = request_bytes(ROOT, role='builder')
        with patch('factory_runtime.pilot002_transport.http.client.HTTPSConnection') as connect:
            for enabled, body in ((False, raw), (True, raw+b' ')):
                transport = Handoff003Transport(ROOT, role='builder', enabled=enabled)
                with self.assertRaises(StateError): transport.send_once(request_bytes=body,
                    credential='synthetic-not-a-key-1234', expected_request_digest=sha(body))
            connect.assert_not_called()

    def test_uncertain_send_is_not_retried_and_error_is_redacted(self):
        raw = request_bytes(ROOT, role='builder')
        self.connection.request.side_effect = TimeoutError('sensitive provider detail')
        transport = Handoff003Transport(ROOT, role='builder', enabled=True)
        with patch('factory_runtime.pilot002_transport.http.client.HTTPSConnection', return_value=self.connection):
            for _ in range(2):
                with self.assertRaises(StateError) as error:
                    transport.send_once(request_bytes=raw, credential='synthetic-not-a-key-1234', expected_request_digest=sha(raw))
                self.assertNotIn('sensitive', str(error.exception))
        self.connection.request.assert_called_once()
