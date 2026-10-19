"""Read exact local Git objects without checkout, fetch, hooks or execution.

The deployment must establish repository provenance before supplying this local
object database. A remote URL or commit hash alone is not owner authorization.
"""
from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
import re
import subprocess

from factory_state.model import COMMIT_SHA, StateError
from .task_candidate import _portable_paths


@dataclass(frozen=True)
class RepositoryFile:
    path: str
    content: bytes
    executable: bool


@dataclass(frozen=True)
class RepositorySnapshot:
    repository: str
    commit: str
    files: tuple[RepositoryFile, ...]


def read_repository_snapshot(path, *, repository, commit):
    if (not isinstance(repository, str)
            or not re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', repository)
            or not isinstance(commit, str) or not COMMIT_SHA.fullmatch(commit)):
        raise StateError('repository snapshot requires exact repository and commit')
    root = Path(path).resolve(strict=True)
    # Ignore inherited Git redirection and replacement objects. Never lazy-fetch
    # missing objects in a partial clone or enable optional repository writes.
    env = {k: v for k, v in os.environ.items() if not k.upper().startswith('GIT_')}
    env.update(GIT_NO_REPLACE_OBJECTS='1', GIT_NO_LAZY_FETCH='1', GIT_OPTIONAL_LOCKS='0',
               GIT_TERMINAL_PROMPT='0', GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL=os.devnull)

    def git(*args):
        try:
            return subprocess.run(['git', '-C', str(root), '-c', 'protocol.allow=never',
                *args], env=env, check=True, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, timeout=30).stdout
        except (subprocess.SubprocessError, OSError) as error:
            raise StateError('local repository snapshot unavailable') from error

    if git('rev-parse', '--verify', commit+'^{commit}').decode().strip() != commit:
        raise StateError('snapshot commit differs')
    records = git('ls-tree', '-r', '-z', '-l', '--full-tree', commit).split(b'\0')
    if len(records) > 10001:
        raise StateError('repository snapshot exceeds file count')
    entries, total = [], 0
    for record in filter(None, records):
        metadata, raw_path = record.split(b'\t', 1)
        mode, kind, oid, size = metadata.split()
        if mode not in {b'100644', b'100755'} or kind != b'blob':
            raise StateError('snapshot rejects links and submodules')
        count = int(size)
        total += count
        if count > 16 * 1024 * 1024 or total > 64 * 1024 * 1024:
            raise StateError('repository snapshot exceeds byte limit')
        entries.append((raw_path.decode('utf-8'), mode, oid, count))
    _portable_paths([entry[0] for entry in entries])
    files = []
    for name, mode, oid, size in entries:
        content = git('cat-file', 'blob', oid.decode('ascii'))
        actual = hashlib.sha1(b'blob '+str(len(content)).encode()+b'\0'+content).hexdigest()
        if len(content) != size or actual != oid.decode('ascii'):
            raise StateError('repository blob differs from pinned tree')
        files.append(RepositoryFile(name, content, mode == b'100755'))
    return RepositorySnapshot(repository, commit, tuple(files))
