"""Prepare, execute and verify a disabled acceptance broker in CloudShell.

Preparation creates a reviewable CloudFormation change set, without executing
it. The deployed role can only write to its own existing log group.
"""
from __future__ import annotations

import hashlib
import json
import re
import sys
import uuid
from pathlib import Path

try:
    from .prepare_role_deployment import ACCOUNT, BUCKET, REGION, ROOT, aws, source
except ImportError:
    from prepare_role_deployment import ACCOUNT, BUCKET, REGION, ROOT, aws, source


STACK = 'tims-factory-acceptance-broker'
TEMPLATE = ROOT / 'infra/acceptance/broker-canary.cloudformation.json'
ROLE = 'tims-factory-acceptance-broker-canary'
FUNCTION = 'tims-factory-provider-broker'
EXPECTED_RESOURCES = {'BrokerLogs', 'BrokerRole', 'BrokerFunction', 'BrokerVersion'}


def validate_changes(changes):
    resources = [entry['ResourceChange'] for entry in changes]
    if ({item['LogicalResourceId'] for item in resources} != EXPECTED_RESOURCES or
            len(resources) != len(EXPECTED_RESOURCES) or
            any(item['Action'] != 'Add' for item in resources)):
        raise RuntimeError('broker canary change set must only add four exact resources')


def validate_plan(plan, *, commit, template_digest):
    if (plan.get('source_commit') != commit or
            plan.get('template_sha256') != template_digest or
            plan.get('status') not in {'PREPARED_NOT_EXECUTED', 'DEPLOYED_PENDING_PROBE'} or
            plan.get('model_calls_authorized') != 0 or
            not isinstance(plan.get('artifact'), dict) or
            plan['artifact'].get('source_commit') != commit):
        raise RuntimeError('broker canary plan differs from reviewed source')
    validate_changes(plan['changes'])


def prepare(package, plan_path):
    commit = source()
    if aws('sts', 'get-caller-identity')['Account'] != ACCOUNT:
        raise RuntimeError('wrong AWS account')
    package = Path(package).resolve()
    manifest = json.loads(package.with_suffix('.json').read_text(encoding='utf-8'))
    if (manifest.get('source_commit') != commit or
            manifest.get('sha256') != hashlib.sha256(package.read_bytes()).hexdigest()):
        raise RuntimeError('broker package differs from exact clean checkout')
    key = f'factory-acceptance-broker-packages/{commit}/{manifest["sha256"]}.zip'
    upload = aws('s3api', 'put-object', '--bucket', BUCKET, '--key', key,
                 '--body', str(package), '--checksum-algorithm', 'SHA256',
                 '--checksum-sha256', manifest['code_sha256'])
    version = upload.get('VersionId')
    if not version or version == 'null':
        raise RuntimeError('versioned broker artifact storage is required')
    parameters = [{'ParameterKey': key, 'ParameterValue': value} for key, value in {
        'ArtifactBucket': BUCKET, 'ArtifactKey': key, 'ArtifactVersion': version,
        'CodeSha256': manifest['code_sha256']}.items()]
    aws('cloudformation', 'validate-template', '--template-body', 'file://' + str(TEMPLATE))
    change_name = 'broker-canary-' + commit[:12] + '-' + uuid.uuid4().hex[:8]
    created = aws('cloudformation', 'create-change-set', '--stack-name', STACK,
                  '--change-set-name', change_name, '--change-set-type', 'CREATE',
                  '--template-body', 'file://' + str(TEMPLATE), '--parameters',
                  json.dumps(parameters), '--capabilities', 'CAPABILITY_NAMED_IAM')
    change_arn = created['Id']
    aws('cloudformation', 'wait', 'change-set-create-complete', '--change-set-name', change_arn)
    described = aws('cloudformation', 'describe-change-set', '--change-set-name', change_arn)
    validate_changes(described['Changes'])
    plan = {'source_commit': commit, 'artifact': manifest, 'change_set_arn': change_arn,
            'template_sha256': hashlib.sha256(TEMPLATE.read_bytes()).hexdigest(),
            'changes': described['Changes'], 'status': 'PREPARED_NOT_EXECUTED',
            'model_calls_authorized': 0}
    Path(plan_path).write_text(json.dumps(plan, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(plan, indent=2))


def execute(plan_path):
    plan_path = Path(plan_path)
    plan = json.loads(plan_path.read_text(encoding='utf-8'))
    commit = source()
    if aws('sts', 'get-caller-identity')['Account'] != ACCOUNT:
        raise RuntimeError('wrong AWS account')
    validate_plan(plan, commit=commit, template_digest=hashlib.sha256(TEMPLATE.read_bytes()).hexdigest())
    if plan['status'] != 'PREPARED_NOT_EXECUTED':
        raise RuntimeError('broker canary plan has already been executed')
    described = aws('cloudformation', 'describe-change-set', '--change-set-name', plan['change_set_arn'])
    validate_changes(described['Changes'])
    if described['Changes'] != plan['changes'] or described['ExecutionStatus'] != 'AVAILABLE':
        raise RuntimeError('broker canary change set differs or cannot execute')
    aws('cloudformation', 'execute-change-set', '--change-set-name', plan['change_set_arn'])
    aws('cloudformation', 'wait', 'stack-create-complete', '--stack-name', STACK)
    plan['status'] = 'DEPLOYED_PENDING_PROBE'
    plan_path.write_text(json.dumps(plan, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({'status': plan['status'], 'source_commit': commit}))


def reconcile(plan_path):
    """Resume after an interrupted waiter without executing the change set again."""
    plan_path = Path(plan_path)
    plan = json.loads(plan_path.read_text(encoding='utf-8'))
    commit = source()
    if aws('sts', 'get-caller-identity')['Account'] != ACCOUNT:
        raise RuntimeError('wrong AWS account')
    validate_plan(plan, commit=commit, template_digest=hashlib.sha256(TEMPLATE.read_bytes()).hexdigest())
    if plan['status'] != 'PREPARED_NOT_EXECUTED':
        raise RuntimeError('broker canary plan is not awaiting reconciliation')
    described = aws('cloudformation', 'describe-change-set', '--change-set-name', plan['change_set_arn'])
    validate_changes(described['Changes'])
    if described['Changes'] != plan['changes'] or described['ExecutionStatus'] != 'EXECUTE_COMPLETE':
        raise RuntimeError('broker canary change set was not executed exactly as prepared')
    stack = aws('cloudformation', 'describe-stacks', '--stack-name', STACK)['Stacks'][0]
    if stack['StackStatus'] != 'CREATE_COMPLETE' or stack['StackId'] != described['StackId']:
        raise RuntimeError('broker canary stack does not match completed change set')
    plan['status'] = 'DEPLOYED_PENDING_PROBE'
    plan_path.write_text(json.dumps(plan, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({'status': plan['status'], 'source_commit': commit, 'reconciled': True}))


def verify(plan_path):
    plan_path = Path(plan_path)
    plan = json.loads(plan_path.read_text(encoding='utf-8'))
    commit = source()
    if aws('sts', 'get-caller-identity')['Account'] != ACCOUNT:
        raise RuntimeError('wrong AWS account')
    validate_plan(plan, commit=commit, template_digest=hashlib.sha256(TEMPLATE.read_bytes()).hexdigest())
    if plan['status'] != 'DEPLOYED_PENDING_PROBE':
        raise RuntimeError('broker canary deployment is not ready for probe')
    stack = aws('cloudformation', 'describe-stacks', '--stack-name', STACK)['Stacks'][0]
    if stack['StackStatus'] != 'CREATE_COMPLETE':
        raise RuntimeError('broker canary stack is not complete')
    outputs = {item['OutputKey']: item['OutputValue'] for item in stack['Outputs']}
    arn = outputs.get('BrokerVersionArn')
    expected_prefix = f'arn:aws:lambda:{REGION}:{ACCOUNT}:function:{FUNCTION}:'
    if not isinstance(arn, str) or not arn.startswith(expected_prefix) or not re.fullmatch(r'[1-9][0-9]*', arn[len(expected_prefix):]):
        raise RuntimeError('broker canary version is not pinned')
    config = aws('lambda', 'get-function-configuration', '--function-name', arn)
    if (config.get('CodeSha256') != plan['artifact']['code_sha256'] or
            config.get('Role') != f'arn:aws:iam::{ACCOUNT}:role/{ROLE}' or
            config.get('Handler') != 'factory_runtime.acceptance_broker_lambda.handler' or
            config.get('Environment', {}).get('Variables') !=
            {'FACTORY_ACCEPTANCE_BROKER_ENABLED': 'false'}):
        raise RuntimeError('broker canary code, role, handler or kill switch differs')
    policy = aws('iam', 'get-role-policy', '--role-name', ROLE,
                 '--policy-name', 'canary-logs-only')['PolicyDocument']
    attached = aws('iam', 'list-attached-role-policies', '--role-name', ROLE)
    inline = aws('iam', 'list-role-policies', '--role-name', ROLE)
    if attached.get('AttachedPolicies') != [] or inline.get('PolicyNames') != ['canary-logs-only']:
        raise RuntimeError('broker canary role has additional policies')
    expected_resource = (f'arn:aws:logs:{REGION}:{ACCOUNT}:log-group:'
                         f'/aws/lambda/{FUNCTION}:*')
    if policy.get('Statement') != [{'Effect': 'Allow',
                                   'Action': ['logs:CreateLogStream', 'logs:PutLogEvents'],
                                   'Resource': expected_resource}]:
        raise RuntimeError('broker canary role has unexpected inline grants')
    nonce = uuid.uuid4().hex
    event = {'kind': 'acceptance_broker_probe', 'source_commit': commit,
             'nonce': nonce, 'task_id': 'deterministic-text-fingerprint'}
    target = plan_path.parent / 'acceptance-broker-probe.json'
    response = aws('lambda', 'invoke', '--function-name', arn,
                   '--invocation-type', 'RequestResponse', '--log-type', 'None',
                   '--cli-binary-format', 'raw-in-base64-out', '--payload',
                   json.dumps(event), str(target))
    if (response.get('FunctionError') or response.get('StatusCode') != 200 or
            response.get('ExecutedVersion') != arn.rsplit(':', 1)[1]):
        raise RuntimeError('broker canary invocation failed')
    proof = json.loads(target.read_text(encoding='utf-8'))
    expected = {'kind': 'acceptance_broker_probe_result', 'source_commit': commit,
                'nonce': nonce, 'task_id': 'deterministic-text-fingerprint',
                'broker_enabled': False, 'provider_calls': 0,
                'credentials_read': False, 'release_dispatched': False}
    if proof != expected:
        raise RuntimeError('broker canary probe differed from model-free expectation')
    evidence = {'source_commit': commit, 'function_arn': arn,
                'artifact_sha256': plan['artifact']['sha256'],
                'status': 'MODEL_FREE_BROKER_PROBE_VERIFIED', 'proof': proof}
    plan_path.with_name('acceptance-broker-canary-evidence.json').write_text(
        json.dumps(evidence, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(evidence, indent=2))


if __name__ == '__main__':
    if len(sys.argv) < 3:
        raise SystemExit('usage: prepare_acceptance_broker_canary.py prepare PACKAGE PLAN | execute PLAN | reconcile PLAN | verify PLAN')
    action = sys.argv[1]
    if action == 'prepare' and len(sys.argv) == 4:
        prepare(sys.argv[2], sys.argv[3])
    elif action == 'execute' and len(sys.argv) == 3:
        execute(sys.argv[2])
    elif action == 'reconcile' and len(sys.argv) == 3:
        reconcile(sys.argv[2])
    elif action == 'verify' and len(sys.argv) == 3:
        verify(sys.argv[2])
    else:
        raise SystemExit('invalid broker canary command')
