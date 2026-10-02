"""Disabled Google broker and isolated durable attempt storage primitives.

Storage binds an already validated approval; it does not authenticate an owner
or authorize spending. No production caller is wired to the attempt store.
"""
import hashlib
import json
import os
import re
from pathlib import Path

from factory_state.model import StateError
from factory_state.scope import canonical

TABLE = 'tims-factory-google-qa-attempts'
ACTIVATION = 'google-qa-pilot-001'
KEY = {'PK': {'S': 'GOOGLE_QA#' + ACTIVATION}, 'SK': {'S': 'ATTEMPT'}}
FLAG = 'FACTORY_GOOGLE_QA_ENABLED'


class GoogleQaAttemptStore:
    """One fixed ledger key across processes, code revisions and request changes."""
    def __init__(self, table_name, client):
        if table_name != TABLE:
            raise StateError('Google QA requires its isolated attempt ledger')
        self.client = client

    def begin(self, *, request_bytes, approval_digest, source_commit):
        if (not isinstance(request_bytes, bytes) or not 0 < len(request_bytes) <= 32768 or
                not isinstance(approval_digest, str) or
                not re.fullmatch(r'sha256:[0-9a-f]{64}', approval_digest) or
                not isinstance(source_commit, str) or not re.fullmatch('[0-9a-f]{40}', source_commit)):
            raise StateError('Google QA attempt binding invalid')
        item = {**KEY, 'status': {'S': 'STARTED'},
            'request_digest': {'S': 'sha256:' + hashlib.sha256(request_bytes).hexdigest()},
            'approval_digest': {'S': approval_digest}, 'source_commit': {'S': source_commit}}
        try:
            self.client.put_item(TableName=TABLE, Item=item,
                ConditionExpression='attribute_not_exists(PK) AND attribute_not_exists(SK)')
        except Exception:
            # Even a timeout before a visible write is uncertain. Do not proceed,
            # retry, refund, expire the row, or substitute a new activation key.
            raise StateError('Google QA attempt exists or is uncertain; reconcile without retry') from None
        return item['request_digest']['S']

    def complete(self, *, request_digest, response):
        if (not isinstance(request_digest, str) or
                not re.fullmatch(r'sha256:[0-9a-f]{64}', request_digest) or
                not isinstance(response, dict) or
                response.get('status') != 'UNAUTHENTICATED_PROVIDER_RESPONSE' or
                response.get('gate_authority') is not False):
            raise StateError('Google QA completion must remain non-authoritative')
        raw = canonical(response)
        if len(raw) > 20000:
            raise StateError('Google QA completion exceeds evidence limit')
        try:
            self.client.update_item(TableName=TABLE, Key=KEY,
                UpdateExpression='SET #s=:done, #r=:response',
                ConditionExpression='#s=:started AND request_digest=:digest',
                ExpressionAttributeNames={'#s': 'status', '#r': 'response'},
                ExpressionAttributeValues={':done': {'S': 'COMPLETE'}, ':started': {'S': 'STARTED'},
                    ':digest': {'S': request_digest}, ':response': {'S': raw.decode()}})
        except Exception:
            raise StateError('Google QA completion uncertain; reconcile without retry') from None


def handler(event, context):
    # There is deliberately no live branch, credential reader or provider client.
    if os.environ.get(FLAG) != 'false':
        raise StateError('Google QA broker remains disabled')
    root = Path(os.environ.get('LAMBDA_TASK_ROOT', '/var/task'))
    commit = json.loads((root / 'BUILD.json').read_bytes())['source_commit']
    if (not isinstance(commit, str) or not re.fullmatch('[0-9a-f]{40}', commit) or
            event != {'kind': 'google_qa_broker_boundary_probe', 'source_commit': commit}):
        raise StateError('Google QA broker only accepts the exact disabled boundary probe')
    return {'status': 'GOOGLE_QA_BROKER_DISABLED', 'source_commit': commit,
        'activation_id': ACTIVATION, 'model_calls': 0, 'secret_reads': 0,
        'ledger_writes': 0, 'task_state_writes': 0,
        'gate_authority': False, 'production_release_authorized': False}
