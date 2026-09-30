"""Create the exact acceptance task state once, as an audited owner override.

This is a model-free bootstrap for the already owner-approved acceptance task.
It creates no lease, queues no dispatch, invokes no provider, and leaves the
schedule disabled. Existing nonmatching authoritative state fails closed.
"""
from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))

from factory_state.dynamodb import DynamoDBStateStore
from factory_state.model import (
    OWNER_IDENTITY, FactoryStateMachine, TaskState,
)

ACCOUNT = '666730517561'
REGION = 'ca-central-1'
TABLE = 'tims-software-factory-state'
FACTORY = 'tims-software-factory'
TASK = 'deterministic-text-fingerprint'
EVENT_ID = 'acceptance-state-bootstrap-20260930'
REASON = (
    'Owner-authorized bootstrap of the bounded deterministic-text-fingerprint '
    'acceptance task to IMPLEMENTATION so the separately authorized independent '
    'Inspector scope review can run before any Builder dispatch.'
)


def _matches(state):
    return (
        state is not None and
        state.factory_id == FACTORY and
        state.task_id == TASK and
        state.state == 'IMPLEMENTATION' and
        state.version == 1 and
        state.updated_by == OWNER_IDENTITY and
        not state.leases and
        not state.consumed_evidence_ids and
        state.remediation is None and
        state.stall is None
    )


def main():
    import boto3
    sts = boto3.client('sts', region_name=REGION)
    if sts.get_caller_identity().get('Account') != ACCOUNT:
        raise RuntimeError('wrong AWS account')
    client = boto3.client('dynamodb', region_name=REGION)
    store = DynamoDBStateStore(TABLE, client)
    current = store.load_state(FACTORY, TASK)
    if current is not None:
        if not _matches(current):
            raise RuntimeError('existing acceptance task state differs from reviewed bootstrap')
        print(json.dumps({
            'status': 'ACCEPTANCE_TASK_STATE_ALREADY_INITIALIZED',
            'state': current.state,
            'version': current.version,
            'updated_by': current.updated_by,
            'model_calls': 0,
            'leases': 0,
        }, sort_keys=True))
        return

    now = datetime.now(timezone.utc)
    before = TaskState(FACTORY, TASK, 'INTAKE', 0, now, OWNER_IDENTITY)
    machine = FactoryStateMachine(before)
    after = machine.owner_override(
        OWNER_IDENTITY, 'IMPLEMENTATION',
        expected_version=0, reason=REASON)
    try:
        store.persist_transition(
            before, after, caller_identity=OWNER_IDENTITY,
            event_id=EVENT_ID, audit_event=machine.last_audit_event)
    except Exception:
        # Reconcile only if AWS actually committed the exact intended state.
        observed = store.load_state(FACTORY, TASK)
        if not _matches(observed):
            raise
        after = observed
    verified = store.load_state(FACTORY, TASK)
    if not _matches(verified):
        raise RuntimeError('acceptance task bootstrap was not durably retained')
    print(json.dumps({
        'status': 'ACCEPTANCE_TASK_STATE_INITIALIZED',
        'state': verified.state,
        'version': verified.version,
        'updated_by': verified.updated_by,
        'model_calls': 0,
        'leases': 0,
    }, sort_keys=True))


if __name__ == '__main__':
    main()
