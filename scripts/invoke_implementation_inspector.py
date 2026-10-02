"""Invoke Inspector 014 once after exact source, safe-state and budget checks."""
import base64
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

import boto3
from botocore.config import Config

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / 'src'), str(ROOT / 'scripts')]
from factory_runtime.implementation_inspector import (
    ACTIVATION, AUTHORIZATION, CANDIDATE, FILES, CONTRACT, PACKET_SHA, digest, validate)
from factory_runtime.inspector_budget import _price
from factory_state.dynamodb import DynamoDBStateStore
from factory_state.scope import SignedScopeStore, canonical
from factory_state.signers import validate_trusted_signers
from verify_inspector_activation_binding import verify, verify_implementation_policy


def main():
    if len(sys.argv) != 3:
        raise SystemExit('usage: invoke_implementation_inspector.py NEW_OUTPUT_DIRECTORY PACKAGE.json')
    output, package = Path(sys.argv[1]), json.loads(Path(sys.argv[2]).read_text())
    if output.exists():
        raise RuntimeError('attempt directory already exists; reconcile, never replay')
    commit = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip()
    if subprocess.check_output(['git', 'status', '--porcelain'], cwd=ROOT, text=True).strip() or package['source_commit'] != commit:
        raise RuntimeError('exact clean package checkout required')
    now = datetime.now(timezone.utc)
    event = {'kind': 'inspector_implementation_review', 'source_commit': commit,
             'authorization_id': AUTHORIZATION, 'candidate_commit': CANDIDATE}
    validate(event, role='inspector', commit=commit, root=ROOT, now=now)
    verify(ROOT)
    _price(json.loads((ROOT / 'factory/evidence/acceptance-inspector-sonnet45-budget-policy-2026-09-30.json').read_text()), now=now)
    config = Config(connect_timeout=3, read_timeout=120, retries={'total_max_attempts': 1, 'mode': 'standard'})
    session = boto3.Session(region_name='ca-central-1')
    if session.client('sts', config=config).get_caller_identity()['Account'] != '666730517561':
        raise RuntimeError('wrong AWS account')
    db = session.client('dynamodb', config=config)
    state = DynamoDBStateStore('tims-software-factory-state', db).load_state('tims-software-factory', 'deterministic-text-fingerprint')
    if state.state != 'INSPECTION' or state.version != 10 or len(state.leases) != 6:
        raise RuntimeError('acceptance state changed; no model call')
    budget_rows = []
    arguments = {'TableName': 'tims-factory-acceptance-budget', 'ConsistentRead': True}
    while True:
        page = db.scan(**arguments)
        budget_rows.extend(page['Items'])
        if not page.get('LastEvaluatedKey'):
            break
        arguments['ExclusiveStartKey'] = page['LastEvaluatedKey']
    if any(row['PK']['S'] == 'INSPECTOR#' + ACTIVATION for row in budget_rows):
        raise RuntimeError('Inspector 014 already reserved; never retry')
    total = sum(int(row.get('reserved_cost_microusd', row.get('reserved_microusd', {'N': '0'}))['N'])
                for row in budget_rows if row['SK']['S'] == 'BUDGET')
    if total != 4870160 or total + 241440 > 5250000:
        raise RuntimeError('overall retained budget differs from approval')
    claim = db.get_item(TableName='tims-factory-acceptance-broker-claims', Key={
        'PK': {'S': 'ACTIVATION#factory-acceptance-commissioning-006'},
        'SK': {'S': 'CALL#5f9245900a50a9376aeadde8b7784e414543facdb0090d9298d54650acec9d29'}}, ConsistentRead=True)['Item']
    response = json.loads(claim['response']['S'])
    if claim['status']['S'] != 'COMPLETE' or response['output_digest'] != 'sha256:d60669619dd3f0a515b84ea4bf7a8154783bf2047f474335b4f31540f38fb048':
        raise RuntimeError('completed Builder artifact differs')
    schedule = session.client('scheduler', config=config).get_schedule(Name='tims-software-factory-autonomy-acceptance')
    if schedule['State'] != 'DISABLED' or schedule['ScheduleExpression'] != 'rate(15 minutes)':
        raise RuntimeError('schedule is not the disabled baseline')
    cf, lam = session.client('cloudformation', config=config), session.client('lambda', config=config)
    versions = {}
    for stack, keys, flag in (
        ('tims-factory-roles', ['PlannerVersionArn', 'BuilderVersionArn', 'InspectorVersionArn'], 'FACTORY_OPERATIONAL_EXECUTION_ENABLED'),
        ('tims-factory-autonomy-controller-disabled', ['ControllerVersionArn'], 'FACTORY_AUTONOMY_CONTROLLER_ENABLED'),
        ('tims-factory-acceptance-broker', ['BrokerVersionArn'], 'FACTORY_ACCEPTANCE_BROKER_ENABLED')):
        description = cf.describe_stacks(StackName=stack)['Stacks'][0]
        if description['StackStatus'] != 'UPDATE_COMPLETE':
            raise RuntimeError('stack deployment incomplete')
        outputs = {x['OutputKey']: x['OutputValue'] for x in description['Outputs']}
        for key in keys:
            arn = outputs[key]
            cfg = lam.get_function_configuration(FunctionName=arn)
            if cfg['Environment']['Variables'][flag] != 'false' or cfg['State'] != 'Active':
                raise RuntimeError('execution flags or version changed')
            if key == 'InspectorVersionArn' and cfg['CodeSha256'] != package['code_sha256']:
                raise RuntimeError('Inspector code differs from verified package')
            versions[key] = arn
    policy = session.client('iam', config=config).get_role_policy(RoleName='tims-factory-executor-inspector',
        PolicyName='acceptance-inspector-fallback-sonnet-4-5')['PolicyDocument']
    verify_implementation_policy(policy)
    output.mkdir(parents=True, exist_ok=False)
    (output / 'event.json').write_text(json.dumps(event, indent=2))
    (output / 'prior-budget-rows.json').write_text(json.dumps(budget_rows, indent=2))
    (output / 'attempt.json').write_text(json.dumps({'utc': now.isoformat(), 'activation_id': ACTIVATION,
        'versions': versions, 'maximum_calls': 1, 'retries': 0, 'overall_cap_usd': '5.25'}))
    response = lam.invoke(FunctionName=versions['InspectorVersionArn'], InvocationType='RequestResponse',
                          Payload=canonical(event))
    raw = response['Payload'].read(65537)
    (output / 'result.json').write_bytes(raw)
    if response.get('FunctionError') or len(raw) > 65536:
        raise RuntimeError('Inspector outcome failed or unknown; do not retry')
    result = json.loads(raw)
    payload = result['payload']
    expected = {'candidate_commit': CANDIDATE, 'contract_digest': CONTRACT,
        'packet_digest': 'sha256:' + PACKET_SHA, 'files_sha256': FILES,
        'source_commit': commit, 'activation_id': ACTIVATION,
        'purpose': 'independent-implementation-review-evidence-only',
        'model_calls': 1, 'provider_calls_remaining': 0, 'operational_execution_enabled': False,
        'production_release_authorized': False}
    if (any(payload.get(k) != v for k, v in expected.items()) or
            payload['assessment_digest'] != digest(canonical(result['assessment'])) or
            payload['independent_tests_digest'] != digest(canonical(result['independent_tests'])) or
            payload['verdict'] != result['assessment']['verdict'] or
            payload['verdict'] not in {'ACCEPTED', 'REJECTED'} or
            result['status'] != 'IMPLEMENTATION_REVIEW_' + payload['verdict']):
        raise RuntimeError('implementation review result binding differs; do not retry')
    keys = validate_trusted_signers(json.loads((ROOT / 'factory/profiles/scope-signers.json').read_text()), now=datetime.now(timezone.utc))
    SignedScopeStore('unused', None, keys)._verify(payload, base64.b64decode(result['signature_base64'], validate=True),
                                                'independent_inspector_service', datetime.now(timezone.utc))
    print(json.dumps({'status': result['status'], 'signature_verified': True,
        'candidate_commit': CANDIDATE, 'tests_passed': result['independent_tests']['tests_passed'],
        'actual_cost_usd': result['assessment']['actual_cost_usd'], 'model_calls': 1,
        'provider_calls_remaining': 0, 'execution_enabled': False}))


if __name__ == '__main__':
    main()
