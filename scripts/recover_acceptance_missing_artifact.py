"""One owner-approved recovery; preserve consumed evidence and every old lease."""
from __future__ import annotations

import json
import sys
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))

from factory_runtime.autonomy_contract import load_autonomy_operating_allowance
from factory_state.dynamodb import DynamoDBStateStore
from factory_state.model import OWNER_IDENTITY, FactoryStateMachine, StateError

FACTORY = 'tims-software-factory'
TASK = 'deterministic-text-fingerprint'
EVENT_ID = 'acceptance-artifact-recovery-005'
EVIDENCE = 'result-ebaf36c94d64d2f29264b50db68410225e767a07ac06819d9ee6a71efb608c0f'
LEASE_IDS = frozenset(('auto-907d1e109b687c151afd34bb',
    'auto-a556ef20cb130af81d499834', 'auto-2d4afbbe6af947b1cbb9591a',
    'auto-293f756b834378cb84d1300f'))
REASON = ('Owner approved one recovery cycle under guarded-commissioning-005-authorization: '
    'commissioning 004 returned clarification instead of implementation files. '
    'Return exact INSPECTION v6 to IMPLEMENTATION, preserve all prior evidence, '
    'leases and budgets, require fresh Inspector 012 and owner signatures, no retries '
    'and no production release. Runtime artifact/context fix: PR 282.')


def prepare(current, now):
    if (current is None or current.factory_id != FACTORY or current.task_id != TASK
            or current.state != 'INSPECTION' or current.version != 6
            or current.updated_by != 'factory_controller_service'
            or current.consumed_evidence_ids != frozenset((EVIDENCE,))
            or frozenset(x.lease_id for x in current.leases) != LEASE_IDS
            or not all(x.revoked and not x.active_at(now) for x in current.leases)):
        raise StateError('recovery requires exact consumed commissioning 004 state; stop')
    machine = FactoryStateMachine(current)
    after = machine.owner_override(OWNER_IDENTITY, 'IMPLEMENTATION',
        expected_version=6, reason=REASON)
    return after, machine.last_audit_event


def main():
    import boto3
    from botocore.config import Config
    if len(sys.argv) != 2:
        raise SystemExit('usage: recover_acceptance_missing_artifact.py NEW_JOURNAL.json')
    allowance = load_autonomy_operating_allowance(ROOT)
    now = datetime.now(timezone.utc)
    if not allowance.commissioning_starts_at <= now < min(
            allowance.commissioning_expires_at, allowance.pricing_expires_at):
        raise StateError('recovery authorization or pricing expired')
    session = boto3.Session(region_name='ca-central-1')
    config = Config(retries={'total_max_attempts': 1})
    def client(name):
        return session.client(name, config=config)
    if client('sts').get_caller_identity()['Account'] != '666730517561':
        raise StateError('wrong AWS account')
    schedule = client('scheduler').get_schedule(Name='tims-software-factory-autonomy-acceptance')
    if schedule['State'] != 'DISABLED':
        raise StateError('recovery requires disabled schedule')
    for name, flag in (
        ('tims-software-factory-autonomy-controller', 'FACTORY_AUTONOMY_CONTROLLER_ENABLED'),
        ('tims-factory-builder', 'FACTORY_OPERATIONAL_EXECUTION_ENABLED'),
        ('tims-factory-provider-broker', 'FACTORY_ACCEPTANCE_BROKER_ENABLED')):
        variables = client('lambda').get_function_configuration(FunctionName=name).get('Environment', {}).get('Variables', {})
        # Any enabled execution flag blocks recovery, regardless of its spelling.
        if variables.get(flag) != 'false' or any(value.lower() == 'true' for key, value in variables.items()
               if key.startswith('FACTORY_') and key.endswith('_ENABLED')):
            raise StateError('recovery requires disabled components: ' + name)
    store = DynamoDBStateStore('tims-software-factory-state', client('dynamodb'))
    before = store.load_state(FACTORY, TASK)
    after, audit = prepare(before, now)
    journal = Path(sys.argv[1])
    with journal.open('x', encoding='utf-8') as handle:
        json.dump({'status': 'ATTEMPTED_NO_RETRY', 'event_id': EVENT_ID,
            'before': asdict(before), 'after': asdict(after), 'audit': audit},
            handle, default=str, indent=2)
    try:
        store.persist_transition(before, after, caller_identity=OWNER_IDENTITY,
            event_id=EVENT_ID, audit_event=audit)
    except Exception:
        if store.load_state(FACTORY, TASK) != after:
            raise
    if store.load_state(FACTORY, TASK) != after:
        raise StateError('recovery not verified; do not retry')
    print(json.dumps({'status': 'OWNER_RECOVERY_VERIFIED', 'state': after.state,
        'version': after.version, 'leases_preserved': len(after.leases),
        'consumed_evidence_preserved': sorted(after.consumed_evidence_ids), 'model_calls': 0}))


if __name__ == '__main__':
    main()
