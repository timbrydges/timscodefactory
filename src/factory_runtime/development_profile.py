"""Operator-owned task execution profiles; inert data, never queue authority."""
from dataclasses import dataclass
import json
import re

from factory_state.model import StateError
from factory_state.scope import canonical
from .task_provider import _path
from .worker import digest


@dataclass(frozen=True)
class TaskExecutionProfile:
    repository: str
    task_id: str
    required_changed_paths: tuple[str, ...]
    test_command: tuple[str, ...]
    timeout_seconds: int = 60

    def __post_init__(self):
        if (type(self.repository) is not str
                or not re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', self.repository)
                or type(self.task_id) is not str
                or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._:-]{0,127}', self.task_id)):
            raise StateError('invalid execution profile identity')
        if (type(self.required_changed_paths) is not tuple
                or not 1 <= len(self.required_changed_paths) <= 50
                or any(type(p) is not str or len(p) > 512 for p in self.required_changed_paths)
                or len(set(self.required_changed_paths)) != len(self.required_changed_paths)):
            raise StateError('invalid execution profile paths')
        for path in self.required_changed_paths:
            _path(path)
        if (type(self.test_command) is not tuple or not 1 <= len(self.test_command) <= 32
                or any(type(arg) is not str or not arg or len(arg) > 1024
                       or any(ord(c) < 32 for c in arg) for arg in self.test_command)
                or type(self.timeout_seconds) is not int
                or not 1 <= self.timeout_seconds <= 60):
            raise StateError('invalid execution profile command or timeout')

    @property
    def delivery(self):
        return {'mode': 'complete_task_single_proposal',
                'required_changed_paths': list(self.required_changed_paths),
                'test_command': list(self.test_command)}

    @property
    def digest(self):
        return digest(canonical({'schema_version': 1, 'repository': self.repository,
            'task_id': self.task_id, 'delivery': self.delivery,
            'timeout_seconds': self.timeout_seconds}))

    def validate_binding(self, *, pins, task, contract_bytes):
        if type(contract_bytes) is not bytes or len(contract_bytes) > 65536:
            raise StateError('execution profile requires bounded contract')
        try:
            spec = json.loads(contract_bytes)
        except (ValueError, UnicodeError):
            raise StateError('invalid execution profile contract') from None
        if (type(spec) is not dict or pins.get('execution_profile_digest') != self.digest
                or pins.get('repository') != self.repository or task.task_id != self.task_id
                or spec.get('repository') != self.repository or spec.get('task_id') != self.task_id
                or type(spec.get('allowed_paths')) is not list
                or any(path not in spec['allowed_paths'] for path in self.required_changed_paths)):
            raise StateError('execution profile differs from approved task')

def read_execution_profile(raw):
    """Decode bounded operator bytes. Does not grant authority or read a path."""
    if type(raw) is not bytes or len(raw) > 16384:
        raise StateError('bounded execution profile required')
    try:
        def unique(pairs):
            result = {}
            for key, value in pairs:
                if key in result:
                    raise ValueError('duplicate key')
                result[key] = value
            return result
        value = json.loads(raw, object_pairs_hook=unique)
        if (type(value) is not dict or set(value) != {
                'repository', 'task_id', 'required_changed_paths', 'test_command', 'timeout_seconds'}
                or type(value['required_changed_paths']) is not list
                or type(value['test_command']) is not list):
            raise ValueError()
        return TaskExecutionProfile(value['repository'], value['task_id'],
            tuple(value['required_changed_paths']), tuple(value['test_command']),
            value['timeout_seconds'])
    except (ValueError, TypeError, UnicodeError):
        raise StateError('invalid operator execution profile') from None
