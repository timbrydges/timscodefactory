"""Disposable proposal application and receipt checking; never execute or advance.

Commands, environments and sandbox adapters remain deployment-owned. This module
does not invoke an adapter, mint approval, publish changes or modify a checkout.
"""
from contextlib import contextmanager
from dataclasses import dataclass
import json
from pathlib import Path
import re
from tempfile import TemporaryDirectory

from factory_state.model import StateError
from factory_state.scope import canonical
from .docker_sandbox import workspace_tree_digest
from .sandbox import SandboxRequest, bind_sandbox_receipt


def _portable_paths(files):
    seen = set()
    prefixes = {}
    for path in files:
        parts = path.split('/')
        if (not re.fullmatch(r'[A-Za-z0-9_./()\[\]@+ -]+', path)
                or any(p in {'', '.', '..'} or p.endswith(('.', ' ')) for p in parts)
                or any(re.fullmatch(r'(?i)(con|prn|aux|nul|com[0-9]|lpt[0-9])(?:\..*)?', p) for p in parts)
                or any(p.lower() in {'.git', '__pycache__', '.pytest_cache'} for p in parts)
                or path.lower() in seen):
            raise StateError('candidate requires distinct portable source paths')
        seen.add(path.lower())
        for index in range(1, len(parts) + 1):
            prefix = '/'.join(parts[:index])
            previous = prefixes.setdefault(prefix.lower(), prefix)
            if previous != prefix:
                raise StateError('candidate directory spelling differs across platforms')
    if any('/'.join(p.split('/')[:i]).lower() in seen
           for p in files for i in range(1, len(p.split('/')))):
        raise StateError('candidate file and directory paths conflict')


@dataclass(frozen=True)
class TaskCandidate:
    workspace: Path
    workspace_digest: str
    input_digest: str
    decision_digest: str
    task_id: str
    target_commit: str

    def request(self, *, request_id, lease_id, role_id, command,
                environment_digest, timeout_seconds, expected_runner_identity):
        """Only trusted composition supplies these execution parameters."""
        if (type(command) is not tuple or not command
                or any(type(arg) is not str or not arg or '\x00' in arg for arg in command)):
            raise StateError('validation requires trusted argv tuple')
        if workspace_tree_digest(self.workspace) != self.workspace_digest:
            raise StateError('candidate changed before validation request')
        return SandboxRequest(request_id=request_id, task_id=self.task_id,
            lease_id=lease_id, role_id=role_id, source_commit=self.target_commit,
            workspace_digest=self.workspace_digest, command=tuple(command),
            environment_digest=environment_digest, timeout_seconds=timeout_seconds,
            expected_runner_identity=expected_runner_identity)

    def evaluate(self, request, receipt, *, now):
        if (request.task_id != self.task_id or request.source_commit != self.target_commit
                or request.workspace_digest != self.workspace_digest
                or workspace_tree_digest(self.workspace) != self.workspace_digest):
            raise StateError('validation differs from exact candidate')
        bound = bind_sandbox_receipt(request, receipt, now=now)
        status = ('TIMED_OUT' if bound.receipt.timed_out else
                  'TESTS_PASSED_REVIEW_REQUIRED' if bound.receipt.exit_code == 0 else 'TESTS_FAILED')
        return {'status': status, 'input_digest': self.input_digest,
                'decision_digest': self.decision_digest, 'workspace_digest': self.workspace_digest,
                'request_digest': bound.request_digest, 'authoritative': False,
                'progression_authorized': False, 'release_authorized': False}


@contextmanager
def candidate_workspace(protocol, decision, *, repository_snapshot=None):
    """Apply a frozen proposal only to a disposable copy of supplied source text.

    Without repository_snapshot this is only the supplied partial source text.
    A deployment-owned snapshot adds the complete pinned Git tree and must match
    every supplied source byte. No commands are run; new files remain unsupported.
    """
    decision = json.loads(canonical(decision))
    checked = protocol.validate_decision(decision)
    if decision.get('type') != 'apply_edits':
        raise StateError('candidate requires an edit proposal')
    turn = protocol.turn
    files = turn['files']
    _portable_paths(files)
    baseline, executable = {}, set()
    if repository_snapshot is not None:
        from .repository_snapshot import RepositorySnapshot
        if (type(repository_snapshot) is not RepositorySnapshot
                or repository_snapshot.repository != turn['repository']
                or repository_snapshot.commit != turn['target_commit']):
            raise StateError('repository snapshot differs from task target')
        _portable_paths([entry.path for entry in repository_snapshot.files])
        baseline = {entry.path: entry.content for entry in repository_snapshot.files}
        executable = {entry.path for entry in repository_snapshot.files if entry.executable}
        if any(baseline.get(path) != content.encode('utf-8') for path, content in files.items()):
            raise StateError('provider source differs from pinned repository')
    for edit in decision['edits']:
        files[edit['path']] = files[edit['path']].replace(edit['old_text'], edit['new_text'], 1)
    if len(canonical(files)) > 65536:
        raise StateError('candidate source exceeds byte limit')
    baseline.update({path: content.encode('utf-8') for path, content in files.items()})
    with TemporaryDirectory(prefix='factory-candidate-') as directory:
        root = Path(directory)
        for path, content in baseline.items():
            destination = root / path
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(content)
            destination.chmod(0o755 if path in executable else 0o644)
        yield TaskCandidate(root, workspace_tree_digest(root), checked['input_digest'],
            checked['decision_digest'], turn['task_id'], turn['target_commit'])
