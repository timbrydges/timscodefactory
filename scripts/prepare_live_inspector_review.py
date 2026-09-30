"""Prepare the exact live Inspector review event; no provider call or state write."""
from __future__ import annotations

import json
import subprocess
import sys
from dataclasses import asdict
from datetime import datetime, timedelta, timezone
from pathlib import Path

import boto3

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT/'src'), str(ROOT/'scripts')]

from factory_runtime.intake import AuthenticatedIntakeService
from factory_runtime.receipt_transport import receipt_plan_digest
from factory_runtime.worker import digest
from factory_state.dispatch import DynamoDBDispatchStore
from factory_state.dynamodb import DynamoDBStateStore
from prepare_acceptance_inspector_prompt import render
from prepare_acceptance_inspector_review import build_packet

ACCOUNT = '666730517561'
REGION = 'ca-central-1'
TABLE = 'tims-software-factory-state'
FACTORY = 'tims-software-factory'
TASK = 'deterministic-text-fingerprint'
ACTIVATION = 'inspector-fallback-2026-09-30-001'
AUTHORIZATION = 'acceptance-inspector-sonnet45-fallback-authorization-2026-09-30'


def source():
    commit = subprocess.check_output(
        ['git', '-C', str(ROOT), 'rev-parse', 'HEAD'], text=True).strip()
    if subprocess.check_output(
            ['git', '-C', str(ROOT), 'status', '--porcelain'], text=True).strip():
        raise RuntimeError('exact clean checkout required')
    return commit


def main():
    if len(sys.argv) != 2:
        raise SystemExit('usage: prepare_live_inspector_review.py OUT.json')
    now = datetime.now(timezone.utc)
    if boto3.client('sts', region_name=REGION).get_caller_identity()['Account'] != ACCOUNT:
        raise RuntimeError('wrong AWS account')
    contract = (ROOT/'factory/autonomy/acceptance-contract.json').read_bytes()
    task_input = (ROOT/'factory/autonomy/acceptance-input.txt').read_bytes()
    if digest(contract) != 'sha256:7ca5363f88bc43e31436e1c8640bb9516a705aa07dda82519a690a9301a9b9fa':
        raise RuntimeError('contract bytes differ')
    if digest(task_input) != 'sha256:e1aefa3eb9e1d4251c15285a353d1b8abbf0076acd515bff13133894a6a48418':
        raise RuntimeError('input bytes differ')

    client = boto3.client('dynamodb', region_name=REGION)
    states = DynamoDBStateStore(TABLE, client)
    state = states.load_state(FACTORY, TASK)
    if state is None:
        print(json.dumps({'status':'ACCEPTANCE_TASK_STATE_MISSING','model_calls':0}))
        raise SystemExit(2)
    if state.state != 'IMPLEMENTATION':
        print(json.dumps({'status':'ACCEPTANCE_TASK_STATE_NOT_IMPLEMENTATION',
                          'state':state.state,'version':state.version,'model_calls':0}))
        raise SystemExit(3)

    service = AuthenticatedIntakeService(
        states, DynamoDBDispatchStore(TABLE, client), key_loader=(lambda _at: {}), clock=lambda: now)
    plan = service.prepare(
        FACTORY, TASK, role_id='engineering_agent', source_commit=source(),
        objective_id='autonomy', capability_id='acceptance',
        contract_bytes=contract, input_bytes=task_input,
        reviewer_identity='independent_inspector_service',
        required_evidence='Exact immutable acceptance contract and independent Inspector decision',
        stop_condition='Stop before any unreviewed Builder dispatch',
        rationale='Independent Inspector review of exact acceptance scope',
        lease_seconds=3600, receipt_seconds=1800)

    stack = boto3.client('cloudformation', region_name=REGION).describe_stacks(
        StackName='tims-factory-roles')['Stacks'][0]
    outputs = {x['OutputKey']:x['OutputValue'] for x in stack.get('Outputs',[])}
    builder = outputs['BuilderVersionArn']
    inspector = outputs['InspectorVersionArn']
    binding = {
        'activation_id': ACTIVATION,
        'source_commit': source(),
        'contract_digest': digest(contract),
        'starts_at': (now-timedelta(minutes=1)).isoformat(),
        'expires_at': (now+timedelta(hours=2)).isoformat(),
        'builder_version_arn': builder,
    }
    document = asdict(plan)
    document['lease']['expires_at'] = plan.lease.expires_at.isoformat()
    document['plan_digest'] = receipt_plan_digest(plan)
    request = render(build_packet(binding, document, task_input, contract, now=now))
    event = {'kind':'inspector_live_review','source_commit':source(),'task_id':TASK,
             'authorization_id':AUTHORIZATION,'plan':document,'request':request}
    Path(sys.argv[1]).write_text(
        json.dumps(event, sort_keys=True, indent=2)+'\n', encoding='utf-8')
    print(json.dumps({'status':'LIVE_INSPECTOR_EVENT_PREPARED_NOT_INVOKED',
        'state':state.state,'state_version':state.version,
        'plan_digest':document['plan_digest'],'inspector_version_arn':inspector,
        'model_calls':0,'state_mutations':0}, sort_keys=True))


if __name__ == '__main__':
    main()
