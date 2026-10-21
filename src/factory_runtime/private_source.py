"""Explicitly enabled private-source acquisition; no token issuer is installed here.

The trusted host injects issuance/revocation and invokes this before candidate
execution. Construction/import never reads credentials or makes requests.
"""
from dataclasses import dataclass, field
from datetime import datetime
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess

from factory_state.model import StateError
from .repository_snapshot import read_repository_snapshot


@dataclass(frozen=True)
class SourceBinding:
    repository: str
    repository_id: int
    commit: str
    manifest_digest: str

    def validate(self):
        if (type(self.repository) is not str
                or not re.fullmatch(r'[A-Za-z0-9_-][A-Za-z0-9_.-]*/[A-Za-z0-9_-][A-Za-z0-9_.-]*', self.repository)
                or type(self.repository_id) is not int or self.repository_id <= 0
                or type(self.commit) is not str or not re.fullmatch(r'[0-9a-f]{40}', self.commit)
                or type(self.manifest_digest) is not str
                or not re.fullmatch(r'sha256:[0-9a-f]{64}', self.manifest_digest)):
            raise StateError('exact private source binding required')


@dataclass(frozen=True)
class InstallationLease:
    token: str = field(repr=False)
    expires_at: datetime


def validate_installation_response(response, binding, now):
    """Require positive scope evidence; never infer scope from a token string."""
    binding.validate()
    try:
        expires = datetime.fromisoformat(response['expires_at'].replace('Z', '+00:00'))
        repos = response['repositories']
        token = response['token']
        valid = (now.tzinfo is not None and expires.tzinfo is not None
            and 60 < (expires - now).total_seconds() <= 3600
            and response['permissions'] == {'contents': 'read', 'metadata': 'read'}
            and type(repos) is list and len(repos) == 1
            and type(repos[0]['id']) is int and repos[0]['id'] == binding.repository_id
            and repos[0]['full_name'] == binding.repository
            and type(token) is str and 16 <= len(token) <= 32768
            and all(33 <= ord(c) <= 126 for c in token))
    except (KeyError, TypeError, ValueError, AttributeError):
        valid = False
    if not valid:
        raise StateError('installation response scope or expiry rejected')
    return InstallationLease(token, expires)


def snapshot_manifest_digest(snapshot):
    entries = [{'path': f.path, 'sha256': hashlib.sha256(f.content).hexdigest(),
                'executable': f.executable} for f in sorted(snapshot.files, key=lambda f: f.path)]
    raw = json.dumps(entries, sort_keys=True, separators=(',', ':')).encode()
    return 'sha256:' + hashlib.sha256(raw).hexdigest()


def _remove_objects(objects):
    """Git marks loose objects read-only on Windows; remove only this owned tree."""
    def remove_readonly(function, path, error):
        target = Path(path)
        if (os.name != 'nt' or not issubclass(error[0], PermissionError)
                or target.is_symlink() or not target.resolve().is_relative_to(objects.resolve())
                or not target.is_file() or target.stat().st_mode & stat.S_IWRITE):
            raise error[1]
        target.chmod(target.stat().st_mode | stat.S_IWRITE)
        function(path)
    shutil.rmtree(objects, onerror=remove_readonly)


class GitHubObjectFetch:
    """One Git HTTPS fetch, with credentials only in the short-lived child env.

    No checkout, hooks, submodules, persistent remote or credential helper.
    A deployment must additionally provide a disk quota for the object store.
    """
    def __init__(self, git_executable, *, enabled=False, run=subprocess.run):
        self.git = str(git_executable)
        self.enabled = enabled
        self.run = run

    def __call__(self, directory, binding, lease):
        if self.enabled is not True:
            raise StateError('private Git transport disabled')
        binding.validate()
        if not Path(self.git).is_absolute():
            raise StateError('trusted absolute Git executable required')
        directory = Path(directory)
        if directory.is_symlink() or not directory.is_dir() or any(directory.iterdir()):
            raise StateError('fresh empty object directory required')
        env = {k: os.environ[k] for k in ('SystemRoot', 'WINDIR', 'TEMP', 'TMP') if k in os.environ}
        env.update(GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL=os.devnull,
                   GIT_TERMINAL_PROMPT='0', GIT_NO_REPLACE_OBJECTS='1', GIT_NO_LAZY_FETCH='1')
        config = ['-c', 'core.hooksPath='+os.devnull, '-c', 'credential.helper=',
                  '-c', 'protocol.allow=never', '-c', 'protocol.https.allow=always',
                  '-c', 'http.followRedirects=false', '-c', 'http.sslVerify=true']
        def invoke(args):
            try:
                self.run([self.git, *config, *args], env=env, check=True,
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                         timeout=60, stdin=subprocess.DEVNULL)
            except (subprocess.SubprocessError, OSError):
                raise StateError('private Git operation failed; no retry') from None
        invoke(['init', '--bare', '--template=', str(directory)])
        header = base64.b64encode(('x-access-token:'+lease.token).encode()).decode()
        env.update(GIT_CONFIG_COUNT='1', GIT_CONFIG_KEY_0='http.https://github.com/.extraHeader',
                   GIT_CONFIG_VALUE_0='Authorization: Basic '+header)
        try:
            invoke(['-C', str(directory), 'fetch', '--depth=1', '--no-tags',
                    '--no-recurse-submodules', 'https://github.com/'+binding.repository+'.git', binding.commit])
        finally:
            env.clear()


def fetch_private_snapshot(directory, *, binding, issue_token, revoke_token,
                           fetch_objects, clock, enabled=False, owner_authorized=False,
                           read_snapshot=read_repository_snapshot):
    """Return an existing RepositorySnapshot only after revocation and cleanup.

    The exclusive attempt directory is retained as a no-retry marker. A failed
    issuer may have issued a token: that state is uncertain, never retried.
    """
    if enabled is not True or owner_authorized is not True:
        raise StateError('private source acquisition requires explicit authorization')
    binding.validate()
    root = Path(directory)
    if (not root.is_absolute() or root.parent.is_symlink() or not root.parent.is_dir()
            or root.parent.resolve() != root.parent):
        raise StateError('existing trusted source parent required')
    root.mkdir(exist_ok=False)
    receipt = root / 'source-fetch.json'
    state = dict(status='STARTED', repository=binding.repository, repository_id=binding.repository_id,
                 commit=binding.commit, manifest_digest=binding.manifest_digest,
                 issuance_started=False, fetch_started=False, revocation_confirmed=False,
                 object_cleanup=False)
    def save():
        with receipt.open('w', encoding='utf-8') as handle:
            json.dump(state, handle, sort_keys=True)
            handle.flush()
            os.fsync(handle.fileno())
    save()
    objects = root / 'objects'
    response = None
    token = None
    snapshot = None
    failed = False
    try:
        objects.mkdir()
        state['issuance_started'] = True
        save()
        response = issue_token(repository_ids=[binding.repository_id], permissions={'contents': 'read', 'metadata': 'read'})
        if type(response) is dict and type(response.get('token')) is str:
            token = response['token']
        lease = validate_installation_response(response, binding, clock())
        response = None
        if (lease.expires_at - clock()).total_seconds() <= 60:
            raise StateError('lease expired before fetch')
        state['fetch_started'] = True
        save()
        fetch_objects(objects, binding, lease)
        snapshot = read_snapshot(objects, repository=binding.repository, commit=binding.commit)
        if (snapshot.repository != binding.repository or snapshot.commit != binding.commit
                or snapshot_manifest_digest(snapshot) != binding.manifest_digest):
            raise StateError('fetched source differs from binding')
    except Exception:
        failed = True
    except BaseException:
        failed = True
        raise
    finally:
        response = None
        if token is not None:
            try:
                if revoke_token(token) is not True:
                    raise StateError('revocation unconfirmed')
                state['revocation_confirmed'] = True
            except Exception:
                failed = True
        else:
            failed = True
        token = None
        try:
            if objects.is_symlink():
                raise StateError('unexpected object directory link')
            if objects.exists():
                _remove_objects(objects)
            state['object_cleanup'] = True
        except Exception:
            failed = True
        state['status'] = 'STOPPED_NEEDS_RECONCILIATION' if failed else 'VERIFIED'
        save()
    if failed:
        raise StateError('private source acquisition stopped; inspect receipt, no retry') from None
    return snapshot
