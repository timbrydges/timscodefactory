"""Pinned Builder context and structural artifact validation; never execute code."""
from __future__ import annotations

import ast
import hashlib
import json
from pathlib import Path

from factory_state.model import StateError

PATHS = {'fingerprint.py', 'tests/test_fingerprint.py'}


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate field')
        result[key] = value
    return result


def builder_context(root: Path, request: str) -> str:
    """The source commit pins the contract, task request and starting snapshot."""
    def read(name):
        raw = (root / name).read_bytes()
        if len(raw) > 16384:
            raise ValueError('context exceeds limit')
        return raw, json.loads(raw, object_pairs_hook=_unique)

    try:
        raw, contract = read('factory/autonomy/acceptance-contract.json')
        _, evidence = read('factory/evidence/autonomy-acceptance-repository-2026-09-23.json')
        _, snapshot = read('factory/autonomy/acceptance-source-snapshot.json')
        if (hashlib.sha256(raw).hexdigest() != evidence['contract_sha256'] or
                contract['allowed_write_paths'] != ['fingerprint.py', 'tests/test_fingerprint.py'] or
                set(snapshot) != {'repository', 'base_commit', 'files'} or
                snapshot['repository'] != evidence['repository_full_name'] or
                snapshot['base_commit'] != evidence['contract_commit'] or
                snapshot['files'] != {name: None for name in PATHS}):
            raise ValueError('context binding differs')
    except (OSError, ValueError, KeyError, TypeError) as error:
        raise StateError('acceptance Builder context is missing or invalid') from error
    return json.dumps({'request': request, 'contract': contract, 'source': snapshot},
                      ensure_ascii=False, sort_keys=True, separators=(',', ':'))


def validate_builder_artifacts(raw: bytes) -> None:
    """Require both complete Python sources before a successful role receipt.

    This establishes an artifact shape, not correctness, test success or release
    approval. Independent inspection must still test the exact candidate commit.
    """
    try:
        if not isinstance(raw, bytes) or len(raw) > 65536:
            raise ValueError('artifact exceeds limit')
        document = json.loads(raw.decode('utf-8'), object_pairs_hook=_unique)
        if (not isinstance(document, dict) or set(document) != {'schema_version', 'files'} or
                document['schema_version'] != '1.0' or
                not isinstance(document['files'], dict) or set(document['files']) != PATHS):
            raise ValueError('artifact fields differ')
        for name, content in document['files'].items():
            if not isinstance(content, str) or not content.strip():
                raise ValueError('empty source')
            if not ast.parse(content, filename=name).body:
                raise ValueError('source has no statements')
    except (ValueError, TypeError, SyntaxError, RecursionError) as error:
        raise StateError('acceptance Builder did not return both valid source artifacts; do not retry') from error
