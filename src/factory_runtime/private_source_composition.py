"""Disabled composition of the reviewed private-source pieces.

Hash-pinned operator configuration -> one fingerprint-bound app signature ->
one scoped installation token -> one exact-commit object fetch -> revocation.
The exclusive attempt directory and its receipt are written by
``fetch_private_snapshot`` before signing, so they are the durable no-retry
reservation. Import and configuration loading never read a key, sign, or
make a request. Configuration contains identifiers and paths, never secrets.
"""
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import re
import shutil

from factory_state.model import StateError
from .private_source import GitHubObjectFetch, SourceBinding, fetch_private_snapshot
from .source_app_jwt import issue_app_credential
from .source_key_signer import SourceKeySigner
from .source_token_transport import SourceTokenTransport
from .workload_identity_response import _unique

_FIELDS = {'schema', 'app_client_id', 'installation_id', 'repository', 'repository_id',
           'git_executable', 'signer_executable', 'key_path', 'public_fingerprint',
           'attempt_parent'}
_PERMISSIONS = {'contents': 'read', 'metadata': 'read'}
# factory-bonus-source-storage-v1: the attempt parent must be a dedicated
# fixed-size volume, so Git cannot write more than this before size checks.
ATTEMPT_VOLUME_MAX_BYTES = 256 * 1024 * 1024


@dataclass(frozen=True)
class PrivateSourceConfiguration:
    approval_digest: str
    app_client_id: str
    installation_id: int
    repository: str
    repository_id: int
    git_executable: Path
    signer_executable: Path
    key_path: Path
    public_fingerprint: str
    attempt_parent: Path

    def validate(self):
        if (type(self.approval_digest) is not str
                or not re.fullmatch(r'sha256:[0-9a-f]{64}', self.approval_digest)
                or type(self.app_client_id) is not str
                or not re.fullmatch(r'[A-Za-z0-9]{8,64}', self.app_client_id)
                or any(type(v) is not int or v <= 0 for v in (self.installation_id, self.repository_id))
                or type(self.public_fingerprint) is not str
                or not re.fullmatch(r'SHA256:[A-Za-z0-9+/]{43}=', self.public_fingerprint)):
            raise StateError('exact private source configuration required')
        SourceBinding(self.repository, self.repository_id, '0'*40, 'sha256:'+'0'*64).validate()
        paths = (self.git_executable, self.signer_executable, self.key_path, self.attempt_parent)
        if any(not isinstance(p, Path) or not p.is_absolute() for p in paths):
            raise StateError('absolute trusted paths required')
        if self.attempt_parent in (self.key_path, *self.key_path.parents):
            raise StateError('attempt directory must not contain the app key')


def read_private_source_configuration(path, expected_digest, *, owner_authorized=False):
    """Load the strict operator file; the digest is a local pin, not a signature."""
    if owner_authorized is not True:
        raise StateError('explicit operator authorization required')
    path = Path(path)
    if path.is_symlink() or not path.is_file():
        raise StateError('regular operator configuration required')
    with path.open('rb') as handle:
        raw = handle.read(8193)
    actual = 'sha256:' + hashlib.sha256(raw).hexdigest()
    if not 1 <= len(raw) <= 8192 or expected_digest != actual:
        raise StateError('private source configuration digest mismatch')
    try:
        data = json.loads(raw.decode('utf-8'), object_pairs_hook=_unique)
    except (ValueError, UnicodeError):
        raise StateError('invalid private source configuration') from None
    if (type(data) is not dict or set(data) != _FIELDS
            or type(data['schema']) is not int or data['schema'] != 1
            or any(type(data[k]) is not str for k in ('git_executable', 'signer_executable',
                                                      'key_path', 'attempt_parent'))):
        raise StateError('unsupported private source configuration')
    config = PrivateSourceConfiguration(
        approval_digest=actual, app_client_id=data['app_client_id'],
        installation_id=data['installation_id'], repository=data['repository'],
        repository_id=data['repository_id'], git_executable=Path(data['git_executable']),
        signer_executable=Path(data['signer_executable']), key_path=Path(data['key_path']),
        public_fingerprint=data['public_fingerprint'], attempt_parent=Path(data['attempt_parent']))
    config.validate()
    return config


def acquire_private_source(config, binding, attempt_name, *, clock, enabled=False,
                           owner_authorized=False, run=None, connection=None,
                           acquire=fetch_private_snapshot, disk_usage=shutil.disk_usage):
    """Run at most one bounded acquisition; any failure stops for reconciliation.

    ``clock`` returns an aware datetime. ``run``/``connection`` exist only for
    offline tests; production uses the reviewed subprocess/HTTPS defaults.
    """
    if enabled is not True or owner_authorized is not True:
        raise StateError('private source acquisition requires explicit authorization')
    if not isinstance(config, PrivateSourceConfiguration) or not isinstance(binding, SourceBinding):
        raise StateError('exact configuration and binding required')
    config.validate()
    binding.validate()
    if (binding.repository, binding.repository_id) != (config.repository, config.repository_id):
        raise StateError('task binding differs from approved repository')
    if type(attempt_name) is not str or not re.fullmatch(r'[a-z0-9][a-z0-9-]{0,62}', attempt_name):
        raise StateError('bounded attempt name required')
    parent = config.attempt_parent
    try:
        total = disk_usage(parent).total if parent.is_dir() and not parent.is_symlink() else None
    except OSError:
        total = None
    if type(total) is not int or not 0 < total <= ATTEMPT_VOLUME_MAX_BYTES:
        # An unattached volume leaves an ordinary folder on the system drive.
        raise StateError('attempt parent is not the approved bounded volume')
    extra = {} if run is None else {'run': run}
    signer = SourceKeySigner(config.signer_executable, config.key_path, config.public_fingerprint,
                             enabled=True, owner_authorized=True, **extra)
    transport = SourceTokenTransport(config.installation_id, config.repository_id, enabled=True,
                                     **({} if connection is None else {'connection': connection}))
    fetcher = GitHubObjectFetch(config.git_executable, enabled=True, **extra)
    issued = []

    def issue_token(*, repository_ids, permissions):
        # Single use even if a caller attempted to invoke it again.
        if issued or repository_ids != [config.repository_id] or permissions != _PERMISSIONS:
            raise StateError('source issuance consumed or scope rejected')
        issued.append(True)
        credential = issue_app_credential(
            config.app_client_id, clock=lambda: int(clock().timestamp()), sign_rs256=signer,
            enabled=True, owner_authorized=True)
        try:
            return transport.issue(credential.value, repository_ids=repository_ids,
                                   permissions=permissions)
        finally:
            del credential

    return acquire(config.attempt_parent / attempt_name, binding=binding,
                   issue_token=issue_token, revoke_token=transport.revoke,
                   fetch_objects=fetcher, clock=clock, enabled=True, owner_authorized=True)
