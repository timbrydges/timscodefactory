"""Unsigned fixed-candidate QA execution; no AWS clients or publication path."""
import json
import os
import re
from pathlib import Path

from factory_state.model import StateError
from .implementation_inspector import CANDIDATE
from .qa_execution import execute


def handler(event, context):
    if (os.environ.get('FACTORY_REVIEW_ROLE') != 'qa' or
            os.environ.get('FACTORY_OPERATIONAL_EXECUTION_ENABLED') != 'false'):
        raise StateError('only disabled unsigned QA execution is available')
    root = Path(os.environ.get('LAMBDA_TASK_ROOT','/var/task'))
    commit = json.loads((root/'BUILD.json').read_bytes())['source_commit']
    if (not isinstance(commit,str) or not re.fullmatch('[0-9a-f]{40}',commit) or
            event != {'kind':'qa_execute_unsigned','source_commit':commit,'candidate_commit':CANDIDATE}):
        raise StateError('unsigned QA event differs from pinned source and candidate')
    return {'source_commit':commit,'report':execute(root),
            'model_calls':0,'secret_reads':0,'kms_calls':0,'task_state_writes':0,
            'gate_authority':False,'production_release_authorized':False}
