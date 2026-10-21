"""Explicitly enabled host adapter; construction never reads the app key."""
import base64
import hashlib
import os
from pathlib import Path
import subprocess

from factory_state.model import StateError


class SourceKeySigner:
    """One consumed signing operation after public fingerprint verification.

    The host must verify ACLs and reserve a durable attempt before construction.
    Only trusted, administrator-controlled executable and key paths are allowed.
    No private key bytes or command output are logged or persisted.
    """
    def __init__(self, executable, key_path, public_fingerprint, *, enabled=False,
                 owner_authorized=False, run=subprocess.run):
        self.executable = Path(executable)
        self.key_path = Path(key_path)
        self.public_fingerprint = public_fingerprint
        self.enabled = enabled
        self.owner_authorized = owner_authorized
        self.run = run
        self.consumed = False

    def __call__(self, message):
        if self.enabled is not True or self.owner_authorized is not True or self.consumed:
            raise StateError('source key signing disabled or consumed')
        if (type(message) is not bytes or len(message) > 2048
                or not message or message.count(b'.') != 1):
            raise StateError('bounded JWT signing input required')
        for path in (self.executable, self.key_path):
            if not path.is_absolute() or path.resolve() != path or not path.is_file():
                raise StateError('trusted absolute signer paths required')
        self.consumed = True
        env = {k:os.environ[k] for k in ('SystemRoot','WINDIR','TEMP','TMP') if k in os.environ}
        env['OPENSSL_CONF'] = os.devnull
        try:
            public = self.run([str(self.executable),'rsa','-in',str(self.key_path),
                '-pubout','-outform','DER'], input=b'', stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL, check=True, timeout=10, env=env).stdout
            if type(public) is not bytes or len(public) > 4096:
                raise ValueError()
            fingerprint = 'SHA256:'+base64.b64encode(hashlib.sha256(public).digest()).decode()
            if fingerprint != self.public_fingerprint:
                raise ValueError()
            signature = self.run([str(self.executable),'dgst','-sha256','-sign',str(self.key_path),
                '-sigopt','rsa_padding_mode:pkcs1'], input=message, stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL, check=True, timeout=10, env=env).stdout
            if type(signature) is not bytes or len(signature) not in (256,384,512):
                raise ValueError()
            return signature
        except Exception:
            raise StateError('source key signing stopped; no retry') from None
        finally:
            env.clear()
