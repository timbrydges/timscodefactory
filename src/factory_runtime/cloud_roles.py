"""Bounded Lambda role transport and isolated role-side execution service.

Deployment must restrict InvokeFunction to the controller and configure separate
role credentials. There is no Function URL, dynamic endpoint, implicit retry,
model allowance or scheduler here. Signing keys never enter the controller.
"""
from __future__ import annotations

import base64
import json
import re
from dataclasses import asdict

from factory_state.dispatch import DispatchRequest, DynamoDBDispatchStore
from factory_state.model import StateError
from factory_state.scope import SignedScopeStore, canonical
from .worker import SignedResult, digest

ROLE_IDENTITIES = {
    'planner': 'software_architect_service',
    'builder': 'engineering_agent_service',
    'inspector': 'independent_inspector_service',
}
FUNCTION = re.compile(r'^arn:aws:lambda:ca-central-1:666730517561:function:tims-factory-(planner|builder|inspector):([1-9][0-9]*)$')
MAX_INPUT = 65536
MAX_WIRE = 128 * 1024


def _decode(value, maximum):
    if not isinstance(value, str) or len(value) > ((maximum + 2) // 3) * 4:
        raise StateError('invalid bounded role bytes')
    try:
        raw = base64.b64decode(value, validate=True)
    except ValueError as error:
        raise StateError('invalid role byte encoding') from error
    if len(raw) > maximum:
        raise StateError('role bytes exceed limit')
    return raw


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise StateError('duplicate role response field')
        result[key] = value
    return result


def lambda_client(session):
    """Use normal AWS SigV4 credentials; never inherit an endpoint or retry override."""
    from botocore.config import Config
    return session.client('lambda', region_name='ca-central-1',
        endpoint_url='https://lambda.ca-central-1.amazonaws.com',
        config=Config(connect_timeout=5, read_timeout=65,
                      retries={'total_max_attempts': 1, 'mode': 'standard'}))


class LambdaRoleExecutor:
    """DispatchWorker adapter. The guard is a trusted activation/budget service.

    Each configured function must have a <=60s execution limit. All invocation
    errors, including network timeouts, leave the worker's STARTED record intact.
    No exception is treated as proof that a role did not execute.
    """
    def __init__(self, client, *, function_arn, worker_id, guard):
        match = FUNCTION.fullmatch(function_arn) if isinstance(function_arn, str) else None
        if not match:
            raise StateError('role function requires an exact approved account, name and numeric version')
        # Production callers use lambda_client(); reject accidentally retrying SDK clients.
        if client.meta.config.retries.get('total_max_attempts') != 1:
            raise StateError('role invocation retries must be disabled')
        if client.meta.endpoint_url != 'https://lambda.ca-central-1.amazonaws.com':
            raise StateError('role invocation endpoint must be the regional AWS endpoint')
        from factory_state.model import SAFE_IDENTIFIER
        if not isinstance(worker_id, str) or not SAFE_IDENTIFIER.fullmatch(worker_id):
            raise StateError('invalid controller worker identity')
        self.client, self.function_arn, self.worker_id, self.guard = client, function_arn, worker_id, guard
        self.role, self.version = match.groups()
        self.identity = ROLE_IDENTITIES[self.role]

    def check_activation(self, state, request, *, now):
        return self.guard.check_activation(state, request, now=now)

    def reserve(self, state, request, *, dispatch_id, now):
        return self.guard.reserve(state, request, dispatch_id=dispatch_id, now=now)

    def execute(self, state, request, *, dispatch_id, input_bytes):
        if not isinstance(input_bytes, bytes) or len(input_bytes) > MAX_INPUT or digest(input_bytes) != request.input_digest:
            raise StateError('role input differs from approved dispatch')
        event = {'schema_version': '1.0', 'factory_id': state.factory_id, 'task_id': state.task_id,
            'dispatch_id': dispatch_id, 'worker_id': self.worker_id, 'request': asdict(request),
            'input_base64': base64.b64encode(input_bytes).decode()}
        response = self.client.invoke(FunctionName=self.function_arn,
            InvocationType='RequestResponse', LogType='None', Payload=canonical(event))
        stream = response.get('Payload')
        try:
            if (response.get('StatusCode') != 200 or 'FunctionError' in response or
                    response.get('ExecutedVersion') != self.version or stream is None):
                raise StateError('role invocation failed or executed an unexpected version; reconcile dispatch')
            raw = stream.read(MAX_WIRE + 1)
            if len(raw) > MAX_WIRE:
                raise StateError('role response exceeds bounded format')
            envelope = json.loads(raw, object_pairs_hook=_unique)
            if (not isinstance(envelope, dict) or
                    set(envelope) != {'payload', 'signature_base64', 'output_base64'} or
                    not isinstance(envelope['payload'], dict)):
                raise StateError('invalid signed role response')
            signature = _decode(envelope['signature_base64'], 64)
            if len(signature) != 64:
                raise StateError('invalid role signature length')
            return SignedResult(envelope['payload'], signature, _decode(envelope['output_base64'], MAX_INPUT))
        finally:
            if stream is not None:
                stream.close()


class RoleExecutionService:
    """Runs inside one isolated role, with role-scoped state, signer and backend.

    Backend check_activation/reserve/execute must enforce the approved operating
    contract and cumulative provider budget. Reserve must use dispatch_id as its
    idempotency key, shared with the controller reservation. The backend's execute
    returns bounded bytes; agent output is never a signature request or approval.
    """
    def __init__(self, states, ledger, *, execution_table, deployed_commit, identity, key_loader,
                 signer, backend, clock):
        from factory_state.model import COMMIT_SHA
        if (identity not in ROLE_IDENTITIES.values() or signer.identity != identity or
                not isinstance(deployed_commit, str) or not COMMIT_SHA.fullmatch(deployed_commit)):
            raise StateError('invalid isolated role deployment')
        if not isinstance(execution_table, str) or not execution_table or execution_table == ledger.table_name:
            raise StateError('role execution writes require a separate table')
        self.execution_table = execution_table
        self.states, self.ledger = states, ledger
        self.commit, self.identity = deployed_commit, identity
        self.key_loader, self.signer, self.backend, self.clock = key_loader, signer, backend, clock

    def handle(self, event):
        fields = {'schema_version', 'factory_id', 'task_id', 'dispatch_id', 'worker_id', 'request', 'input_base64'}
        if not isinstance(event, dict) or set(event) != fields or event['schema_version'] != '1.0':
            raise StateError('invalid role invocation envelope')
        from factory_state.model import SAFE_IDENTIFIER
        if any(not isinstance(event[k], str) or not SAFE_IDENTIFIER.fullmatch(event[k])
               for k in ('factory_id', 'task_id', 'dispatch_id', 'worker_id')):
            raise StateError('invalid role invocation identity')
        if not isinstance(event['request'], dict) or set(event['request']) != set(DispatchRequest.__dataclass_fields__):
            raise StateError('invalid role invocation binding')
        request = DispatchRequest(**event['request'])
        input_bytes = _decode(event['input_base64'], MAX_INPUT)
        if request.source_commit != self.commit or request.input_digest != digest(input_bytes):
            raise StateError('role code or input differs from approved dispatch')
        state = self.states.load_state(event['factory_id'], event['task_id'])
        if state is None:
            raise StateError('role task state missing')
        lease = next((x for x in state.leases if x.lease_id == request.lease_id), None)
        if lease is None or lease.authoritative_identity != self.identity:
            raise StateError('dispatch belongs to another role')
        record = self.ledger.read(state, request)
        if (record is None or record.get('dispatch_id') != {'S': event['dispatch_id']} or
                record.get('worker_id') != {'S': event['worker_id']} or
                record.get('status') not in ({'S': 'STARTED'}, {'S': 'RECEIPT_RECORDED'})):
            raise StateError('role dispatch is not claimed by this controller worker')
        key = {'PK': {'S': f'ROLE#{self.identity}#FACTORY#{state.factory_id}#TASK#{state.task_id}'},
               'SK': {'S': f'EXECUTION#{request.lease_id}'}}
        event_digest = digest(canonical(event))
        prior = self.ledger.client.get_item(TableName=self.execution_table, Key=key,
                                            ConsistentRead=True).get('Item')
        if prior:
            if prior.get('event_digest') != {'S': event_digest} or prior.get('identity') != {'S': self.identity}:
                raise StateError('role execution binding conflict')
            if prior.get('status') == {'S': 'COMPLETE'}:
                return json.loads(prior['response']['S'])
            raise StateError('role execution outcome unknown; reconciliation required')
        now = self.clock()
        SignedScopeStore(self.ledger.table_name, self.ledger.client, self.key_loader(now)).verify_persisted(state, request, now=now)
        self.backend.check_activation(state, request, now=now)
        # A conditional durable role-side claim protects against duplicate delivery,
        # even if a caller or infrastructure sends the same invocation twice.
        self.ledger.client.transact_write_items(TransactItems=[
            self.ledger._state_guard(state, request, now),
            *self.ledger._scope_guards(state, request, now),
            {'ConditionCheck': {'TableName': self.ledger.table_name,
                'Key': self.ledger._key(state, request),
                'ConditionExpression': '#s=:s AND worker_id=:w AND dispatch_id=:d AND binding=:b',
                'ExpressionAttributeNames': {'#s': 'status'}, 'ExpressionAttributeValues': {
                    ':s': {'S': 'STARTED'}, ':w': {'S': event['worker_id']},
                    ':d': {'S': event['dispatch_id']}, ':b': {'S': self.ledger._binding(request)}}}},
            {'Put': {'TableName': self.execution_table,
                'Item': {**key, 'status': {'S': 'STARTED'}, 'event_digest': {'S': event_digest},
                         'identity': {'S': self.identity}},
                'ConditionExpression': 'attribute_not_exists(PK) AND attribute_not_exists(SK)'}}])
        self.backend.reserve(state, request, dispatch_id=event['dispatch_id'], now=self.clock())
        now = self.clock()
        SignedScopeStore(self.ledger.table_name, self.ledger.client, self.key_loader(now)).verify_persisted(state, request, now=now)
        self.backend.check_activation(state, request, now=now)
        self.ledger.assert_started(state, request, worker_id=event['worker_id'], now=now)
        output = self.backend.execute(state, request, dispatch_id=event['dispatch_id'], input_bytes=input_bytes)
        if not isinstance(output, bytes) or len(output) > MAX_INPUT:
            raise StateError('role output exceeds bounded format')
        now = self.clock()
        payload = {'kind': 'role_result', 'factory_id': state.factory_id, 'task_id': state.task_id,
            'binding': self.ledger._binding(request), 'dispatch_id': event['dispatch_id'],
            'producer_identity': self.identity, 'output_digest': digest(output),
            'issued_at': int(now.timestamp()), 'expires_at': int(now.timestamp()) + 300}
        signature = self.signer.sign(payload, now=now)
        SignedScopeStore(self.ledger.table_name, self.ledger.client, self.key_loader(now))._verify(
            payload, signature, self.identity, now)
        result = {'payload': payload, 'signature_base64': base64.b64encode(signature).decode(),
                  'output_base64': base64.b64encode(output).decode()}
        self.ledger.client.update_item(TableName=self.execution_table, Key=key,
            UpdateExpression='SET #s=:done, #r=:r',
            ConditionExpression='#s=:started AND event_digest=:d AND #i=:i',
            ExpressionAttributeNames={'#s': 'status', '#r': 'response', '#i': 'identity'}, ExpressionAttributeValues={
                ':done': {'S': 'COMPLETE'}, ':started': {'S': 'STARTED'},
                ':r': {'S': canonical(result).decode()}, ':d': {'S': event_digest}, ':i': {'S': self.identity}})
        return result
