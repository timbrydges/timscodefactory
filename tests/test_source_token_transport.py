import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import Mock

from factory_runtime.source_token_transport import SourceTokenTransport
from factory_state.model import StateError
from factory_runtime.private_source import SourceBinding, fetch_private_snapshot, snapshot_manifest_digest
from factory_runtime.repository_snapshot import RepositorySnapshot, RepositoryFile


class SourceTokenTransportTests(unittest.TestCase):
    def setUp(self):
        self.response = Mock(status=201)
        self.response.read.return_value = b'{"token":"offline-token-only"}'
        self.conn = Mock()
        self.conn.getresponse.return_value = self.response
        self.factory = Mock(return_value=self.conn)
        self.adapter = SourceTokenTransport(100, 200, enabled=True, connection=self.factory)

    def issue(self):
        return self.adapter.issue('offline-jwt-only-value', repository_ids=[200],
            permissions={'contents':'read', 'metadata':'read'})

    def test_exact_request_and_cleanup(self):
        self.assertEqual(self.issue()['token'], 'offline-token-only')
        args, kw = self.conn.request.call_args
        self.assertEqual(args, ('POST','/app/installations/100/access_tokens'))
        self.assertEqual(json.loads(kw['body']), {'repository_ids':[200],
            'permissions':{'contents':'read','metadata':'read'}})
        self.factory.assert_called_once_with('api.github.com', timeout=20)
        self.response.read.assert_called_once_with(65537)
        self.conn.close.assert_called_once()

    def test_disabled_and_scope_rejected_without_network(self):
        self.adapter.enabled = False
        with self.assertRaises(StateError): self.issue()
        self.adapter.enabled = True
        with self.assertRaises(StateError):
            self.adapter.issue('offline-jwt-only-value', repository_ids=[201], permissions={})
        self.factory.assert_not_called()

    def test_bad_credentials_rejected_without_network(self):
        for token in ('x', 'a'*20+'\r\n', 'a'*32769):
            with self.assertRaises(StateError): self.adapter.revoke(token)
        self.factory.assert_not_called()

    def test_redirect_and_errors_never_retried(self):
        for status in (301,302,401,429,500):
            with self.subTest(status=status):
                self.conn.reset_mock()
                self.response.status=status
                with self.assertRaisesRegex(StateError,'no retry'): self.issue()
                self.conn.request.assert_called_once()
                self.conn.close.assert_called_once()

    def test_invalid_and_oversized_responses_stop(self):
        for body in (b'not json',b'[]',b'x'*65537):
            self.response.read.return_value=body
            with self.assertRaises(StateError): self.issue()

    def test_transport_exception_is_redacted(self):
        self.conn.request.side_effect=OSError('secret-value')
        with self.assertRaises(StateError) as caught: self.issue()
        self.assertNotIn('secret-value',str(caught.exception))
        self.conn.request.assert_called_once()
        self.conn.close.assert_called_once()

    def test_revocation_requires_204(self):
        self.response.status=204
        self.response.read.return_value=b''
        self.assertTrue(self.adapter.revoke('offline-token-only'))
        self.assertEqual(self.conn.request.call_args.args,('DELETE','/installation/token'))
        self.assertIsNone(self.conn.request.call_args.kwargs['body'])

    def test_close_failure_is_redacted(self):
        self.conn.close.side_effect=OSError('private-value')
        with self.assertRaises(StateError) as caught: self.issue()
        self.assertNotIn('private-value',str(caught.exception))

    def test_composed_fetch_revokes_even_when_scope_is_rejected(self):
        now = datetime(2026, 10, 20, tzinfo=timezone.utc)
        snapshot = RepositorySnapshot('owner/private', 'a'*40,
            (RepositoryFile('readme.txt', b'offline', False),))
        binding = SourceBinding('owner/private', 200, 'a'*40, snapshot_manifest_digest(snapshot))
        for permission in ('read', 'write'):
            with self.subTest(permission=permission), TemporaryDirectory() as tmp:
                issued = Mock(status=201)
                issued.read.return_value = json.dumps(dict(token='offline-token-only',
                    expires_at=(now+timedelta(minutes=59)).isoformat(),
                    permissions={'contents':permission,'metadata':'read'},
                    repositories=[{'id':200,'full_name':'owner/private'}])).encode()
                revoked = Mock(status=204)
                revoked.read.return_value = b''
                self.conn.reset_mock()
                self.conn.getresponse.side_effect = [issued, revoked]
                fetch = Mock()
                root = Path(tmp).resolve()/'one-attempt'
                def execute():
                    return fetch_private_snapshot(root, binding=binding,
                        issue_token=lambda **kw:self.adapter.issue('offline-jwt-only-value', **kw),
                        revoke_token=self.adapter.revoke, fetch_objects=fetch,
                        read_snapshot=Mock(return_value=snapshot), clock=lambda:now,
                        enabled=True, owner_authorized=True)
                if permission == 'read':
                    self.assertEqual(execute(), snapshot)
                    fetch.assert_called_once()
                else:
                    with self.assertRaises(StateError): execute()
                    fetch.assert_not_called()
                receipt = json.loads((root/'source-fetch.json').read_text())
                self.assertTrue(receipt['revocation_confirmed'])
                self.assertTrue(receipt['object_cleanup'])
                self.assertEqual([call.args[0] for call in self.conn.request.call_args_list], ['POST','DELETE'])
                self.assertNotIn('offline-token-only', (root/'source-fetch.json').read_text())
                with self.assertRaises(FileExistsError): execute()
                self.assertEqual(self.conn.request.call_count, 2)
