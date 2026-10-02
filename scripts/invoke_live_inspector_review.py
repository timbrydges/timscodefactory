"""Invoke the one owner-authorized Inspector review exactly once.

The Inspector runtime reserves the one-call budget before Bedrock. This command
uses an exact Lambda version and disables SDK retries; any uncertain outcome is
terminal and must not be retried.
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import boto3
from botocore.config import Config
from verify_inspector_activation_binding import verify, verify_policy

ROOT = Path(__file__).resolve().parents[1]
ACCOUNT = '666730517561'
REGION = 'ca-central-1'


def source():
    commit = subprocess.check_output(
        ['git', '-C', str(ROOT), 'rev-parse', 'HEAD'], text=True).strip()
    if subprocess.check_output(
            ['git', '-C', str(ROOT), 'status', '--porcelain'], text=True).strip():
        raise RuntimeError('exact clean checkout required')
    return commit


def main():
    if len(sys.argv) != 3:
        raise SystemExit('usage: invoke_live_inspector_review.py EVENT.json OUT.json')
    verify()
    event = json.loads(Path(sys.argv[1]).read_text(encoding='utf-8'))
    if (not isinstance(event, dict) or event.get('kind') != 'inspector_live_review' or
            event.get('source_commit') != source()):
        raise RuntimeError('live Inspector event differs from exact checkout')
    config = Config(connect_timeout=3, read_timeout=120,
                    retries={'total_max_attempts':1, 'mode':'standard'})
    session = boto3.Session(region_name=REGION)
    if session.client('sts', config=config).get_caller_identity()['Account'] != ACCOUNT:
        raise RuntimeError('wrong AWS account')

    cf = session.client('cloudformation', config=config)
    stack = cf.describe_stacks(StackName='tims-factory-roles')['Stacks'][0]
    outputs = {x['OutputKey']:x['OutputValue'] for x in stack.get('Outputs',[])}
    arn = outputs.get('InspectorVersionArn')
    if not isinstance(arn, str) or not arn.startswith(
            'arn:aws:lambda:ca-central-1:666730517561:function:tims-factory-inspector:'):
        raise RuntimeError('exact Inspector version is unavailable')

    lam = session.client('lambda', config=config)
    policy = session.client('iam', config=config).get_role_policy(
        RoleName='tims-factory-executor-inspector',
        PolicyName='acceptance-inspector-fallback-sonnet-4-5')['PolicyDocument']
    verify_policy(policy)
    deployed = lam.get_function_configuration(FunctionName=arn)
    env = deployed.get('Environment',{}).get('Variables',{})
    if (deployed.get('State') != 'Active' or
            deployed.get('LastUpdateStatus') != 'Successful' or
            deployed.get('Role') !=
                'arn:aws:iam::666730517561:role/tims-factory-executor-inspector' or
            env.get('FACTORY_ROLE') != 'inspector' or
            env.get('FACTORY_OPERATIONAL_EXECUTION_ENABLED') != 'false'):
        raise RuntimeError('Inspector version differs from guarded deployment')

    response = lam.invoke(
        FunctionName=arn, InvocationType='RequestResponse',
        Payload=json.dumps(event, sort_keys=True, separators=(',',':')).encode())
    raw = response['Payload'].read(65537)
    if len(raw) > 65536:
        raise RuntimeError('Inspector Lambda response exceeds bound')
    if response.get('FunctionError'):
        Path(sys.argv[2]).write_bytes(raw)
        raise RuntimeError('Inspector review outcome failed or is uncertain; do not retry')
    result = json.loads(raw)
    if (not isinstance(result, dict) or result.get('model_calls') != 1 or
            result.get('provider_calls_remaining') != 0 or
            result.get('operational_execution_enabled') is not False or
            result.get('production_release_authorized') is not False or
            result.get('status') not in {
                'INSPECTOR_REVIEW_ACCEPTED_AND_RECEIPT_PUBLISHED',
                'INSPECTOR_REVIEW_REJECTED'}):
        raise RuntimeError('Inspector review response differs from bounded contract')
    Path(sys.argv[2]).write_text(
        json.dumps(result, sort_keys=True, indent=2)+'\n', encoding='utf-8')
    print(json.dumps({'status':result['status'],'verdict':result['verdict'],
        'actual_cost_usd':result['actual_cost_usd'],
        'reviewer_receipt_version':result['reviewer_receipt_version'],
        'model_calls':1,'provider_calls_remaining':0}, sort_keys=True))


if __name__ == '__main__':
    main()
