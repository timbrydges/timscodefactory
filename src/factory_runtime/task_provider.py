"""Pure task-to-provider protocol; no credentials, network, edits or authority.

The existing OpenAI adapter can consume the returned turn with its deployment-
owned task_implementation policy. Offline tests use only in-memory transport.
"""
import json
from pathlib import PurePosixPath

from factory_state.model import COMMIT_SHA, StateError
from factory_state.scope import canonical
from .worker import digest


def _path(path):
    if (not isinstance(path, str) or not path or '\\' in path or ':' in path
            or PurePosixPath(path).is_absolute() or any(p in {'', '.', '..'} for p in path.split('/'))):
        raise StateError('task file path must be repository relative')
    return path


class TaskImplementationProtocol:
    def __init__(self, task, *, repository, target_commit, contract_bytes, files, missing_paths=()):
        task.validate()
        if (task.expected_state != 'IMPLEMENTATION' or type(contract_bytes) is not bytes
                or len(contract_bytes) > 65536 or digest(contract_bytes) != task.contract_digest
                or type(target_commit) is not str or not COMMIT_SHA.fullmatch(target_commit)):
            raise StateError('implementation requires pinned task and contract')
        spec = json.loads(contract_bytes)
        if (spec.get('repository') != repository or spec.get('target_commit') != target_commit
                or spec.get('task_id') != task.task_id
                or any(spec.get(k) is not False for k in ('execution_authorized', 'spending_authorized',
                                                        'signing_authorized', 'release_authorized'))):
            raise StateError('implementation specification binding differs')
        allowed = spec.get('allowed_paths')
        if not isinstance(allowed, list) or not allowed or len(allowed) > 50:
            raise StateError('exact file scope required')
        self.allowed = frozenset(_path(p) for p in allowed)
        if type(files) is not dict or not files or len(files) > 50:
            raise StateError('bounded source snapshot required')
        self.files = dict(files)
        if any(_path(p) not in self.allowed or type(text) is not str for p, text in self.files.items()):
            raise StateError('source snapshot exceeds file scope')
        if (type(missing_paths) not in {tuple, list} or len(missing_paths) > 50
                or any(_path(p) not in self.allowed or p in self.files for p in missing_paths)
                or len(set(missing_paths)) != len(missing_paths)):
            raise StateError('new files require distinct scoped missing paths')
        self._turn = {'kind': 'factory_task_implementation_v1', 'factory_id': task.factory_id,
            'task_id': task.task_id, 'source_commit': task.source_commit, 'repository': repository,
            'target_commit': target_commit, 'contract_digest': task.contract_digest,
            'source_snapshot_digest': digest(canonical(self.files)), 'specification': spec,
            'files': self.files, 'missing_paths': sorted(missing_paths)}
        self._raw = canonical(self._turn)
        if len(self._raw) > 32000:
            raise StateError('implementation input exceeds byte limit')

    @property
    def turn(self):
        return json.loads(self._raw)

    @property
    def input_digest(self):
        return digest(self._raw)

    def validate_decision(self, decision):
        turn = self.turn  # Always validate against the frozen hashed snapshot.
        files, missing = turn['files'], turn['missing_paths']
        allowed = turn['specification']['allowed_paths']
        if type(decision) is not dict:
            raise StateError('invalid implementation decision')
        kind = decision.get('type')
        if kind == 'read_files' and set(decision) == {'type', 'paths'}:
            paths = decision['paths']
            if not isinstance(paths, list) or not paths or len(paths) > 50:
                raise StateError('bounded read scope required')
            if any(_path(p) not in allowed or p in missing for p in paths):
                raise StateError('provider requested out-of-scope file')
        elif kind == 'apply_edits' and set(decision) == {'type', 'summary', 'edits'}:
            edits = decision['edits']
            if (not isinstance(decision['summary'], str) or not decision['summary'].strip()
                    or not isinstance(edits, list) or not 1 <= len(edits) <= 50):
                raise StateError('invalid proposed edits')
            seen = set()
            for edit in edits:
                if type(edit) is not dict or set(edit) != {'path', 'old_text', 'new_text'}:
                    raise StateError('invalid proposed edit fields')
                path = _path(edit['path'])
                if (path in seen or type(edit['old_text']) is not str
                        or type(edit['new_text']) is not str):
                    raise StateError('edit fields or duplicate path invalid')
                if path in missing:
                    if edit['old_text'] != '' or not edit['new_text']:
                        raise StateError('new file requires empty old text and nonempty content')
                elif (path not in files or not edit['old_text']
                      or files[path].count(edit['old_text']) != 1):
                    raise StateError('edit requires one exact source match in supplied file')
                seen.add(path)
        elif kind == 'escalate' and set(decision) == {'type', 'reason'}:
            if not isinstance(decision['reason'], str) or not decision['reason'].strip():
                raise StateError('escalation requires a reason')
        else:
            raise StateError('unsupported implementation decision')
        if len(canonical(decision)) > 32000:
            raise StateError('implementation proposal exceeds byte limit')
        return {'status': 'ESCALATED' if kind == 'escalate' else 'PROPOSAL_ONLY',
                'input_digest': self.input_digest, 'decision_digest': digest(canonical(decision)),
                'changes_applied': False, 'tests_executed': False}
