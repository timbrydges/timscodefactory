import base64
import hashlib
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import Mock

from factory_runtime.source_key_signer import SourceKeySigner
from factory_state.model import StateError


class SourceKeySignerTests(unittest.TestCase):
    def setUp(self):
        self.tmp=TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name).resolve()
        self.exe=self.root/'fake-executable'; self.exe.write_bytes(b'not executable')
        self.key=self.root/'fake-key'; self.key.write_bytes(b'not a key')
        self.public=b'fake public bytes'
        self.fingerprint='SHA256:'+base64.b64encode(hashlib.sha256(self.public).digest()).decode()
        self.run=Mock(side_effect=[Mock(stdout=self.public),Mock(stdout=b'x'*256)])
        self.signer=SourceKeySigner(self.exe,self.key,self.fingerprint,enabled=True,
            owner_authorized=True,run=self.run)

    def test_one_sign_and_consumption(self):
        self.assertEqual(self.signer(b'header.payload'),b'x'*256)
        self.assertEqual(self.run.call_count,2)
        self.assertEqual(self.run.call_args.kwargs['input'],b'header.payload')
        self.assertIn('rsa_padding_mode:pkcs1',self.run.call_args.args[0])
        with self.assertRaises(StateError):self.signer(b'header.payload')
        self.assertEqual(self.run.call_count,2)

    def test_wrong_fingerprint_prevents_signing(self):
        self.signer.public_fingerprint='wrong'
        with self.assertRaises(StateError):self.signer(b'header.payload')
        self.run.assert_called_once()

    def test_disabled_and_bad_input_do_not_touch_key(self):
        self.signer.enabled=False
        with self.assertRaises(StateError):self.signer(b'header.payload')
        self.signer.enabled=True
        with self.assertRaises(StateError):self.signer(b'x'*2049)
        self.run.assert_not_called()

    def test_timeout_consumed_and_redacted(self):
        self.run.side_effect=OSError('private-path')
        with self.assertRaises(StateError) as caught:self.signer(b'header.payload')
        self.assertNotIn('private-path',str(caught.exception))
        self.assertTrue(self.signer.consumed)
