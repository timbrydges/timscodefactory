"""Update and verify the existing disabled acceptance broker Lambda version.

Only the function code and immutable version may change. The broker role,
permissions, kill switch and log group remain unchanged.
"""
from __future__ import annotations

import hashlib
import json
import re
import sys
import uuid
from pathlib import Path

try:
    from .prepare_acceptance_broker_canary import (
        ACCOUNT, BUCKET, FUNCTION, REGION, ROLE, STACK, TEMPLATE, aws, source,
    )
except ImportError:
    from prepare_acceptance_broker_canary import (
        ACCOUNT, BUCKET, FUNCTION, REGION, ROLE, STACK, TEMPLATE, aws, source,
    )


def validate_changes(changes):
    resources = {entry['ResourceChange']['LogicalResourceId']: entry['ResourceChange']
                 for entry in changes}
    if len(changes) != 2 or set(resources) != {'BrokerFunction', 'BrokerVersion'}:
        raise RuntimeError('broker update must change only function and version')
    function, version = resources['BrokerFunction'], resources['BrokerVersion']
    if (function.get('Action') != 'Modify' or function.get('Replacement') != 'False' or
            version.get('Action') != 'Modify' or version.get('Replacement') != 'True'):
        raise RuntimeError('broker update has an unexpected resource action')
    # CloudFormation details are advisory; these checks supplement the complete
    # reviewed template digest and the post-deployment IAM/flag checks.


def _stack():
    stack = aws('cloudformation', 'describe-stacks', '--stack-name', STACK)['Stacks'][0]
    if stack['StackStatus'] not in {'CREATE_COMPLETE', 'UPDATE_COMPLETE'}:
        raise RuntimeError('broker stack is not ready for an update')
    return stack


def _version(stack):
    outputs = {item['OutputKey']: item['OutputValue'] for item in stack['Outputs']}
    arn = outputs.get('BrokerVersionArn')
    prefix = f'arn:aws:lambda:{REGION}:{ACCOUNT}:function:{FUNCTION}:'
    if not isinstance(arn, str) or not arn.startswith(prefix) or not re.fullmatch(
            r'[1-9][0-9]*', arn[len(prefix):]):
        raise RuntimeError('broker stack output is not a pinned version')
    return arn


def _plan(path, *, required_status):
    plan = json.loads(Path(path).read_text(encoding='utf-8'))
    if (aws('sts', 'get-caller-identity')['Account'] != ACCOUNT or
            plan.get('source_commit') != source() or
            plan.get('template_sha256') != hashlib.sha256(TEMPLATE.read_bytes()).hexdigest() or
            plan.get('status') != required_status or plan.get('model_calls_authorized') != 0 or
            not isinstance(plan.get('artifact'), dict) or
            plan['artifact'].get('source_commit') != plan['source_commit']):
        raise RuntimeError('broker update plan differs from reviewed source')
    validate_changes(plan['changes'])
    if required_status == 'PREPARED_NOT_EXECUTED' and _version(_stack()) != plan['previous_version']:
        raise RuntimeError('broker version changed before update')
    return plan


def prepare(package, plan_path):
    commit = source()
    if aws('sts', 'get-caller-identity')['Account'] != ACCOUNT:
        raise RuntimeError('wrong AWS account')
    before = _stack()
    previous = _version(before)
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
    params = [{'ParameterKey': name, 'ParameterValue': value} for name, value in {
        'ArtifactBucket': BUCKET, 'ArtifactKey': key, 'ArtifactVersion': version,
        'CodeSha256': manifest['code_sha256']}.items()]
    aws('cloudformation', 'validate-template', '--template-body', 'file://' + str(TEMPLATE))
    name = 'broker-update-' + commit[:12] + '-' + uuid.uuid4().hex[:8]
    created = aws('cloudformation', 'create-change-set', '--stack-name', STACK,
                  '--change-set-name', name, '--change-set-type', 'UPDATE',
                  '--template-body', 'file://' + str(TEMPLATE), '--parameters',
                  json.dumps(params), '--capabilities', 'CAPABILITY_NAMED_IAM')
    arn = created['Id']
    aws('cloudformation', 'wait', 'change-set-create-complete', '--change-set-name', arn)
    described = aws('cloudformation', 'describe-change-set', '--change-set-name', arn)
    validate_changes(described['Changes'])
    plan = {'source_commit': commit, 'artifact': manifest, 'change_set_arn': arn,
            'stack_id': before['StackId'], 'previous_version': previous,
            'template_sha256': hashlib.sha256(TEMPLATE.read_bytes()).hexdigest(),
            'changes': described['Changes'], 'status': 'PREPARED_NOT_EXECUTED',
            'model_calls_authorized': 0}
    Path(plan_path).write_text(json.dumps(plan, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(plan, indent=2))


def execute(plan_path):
    plan = _plan(plan_path, required_status='PREPARED_NOT_EXECUTED')
    described = aws('cloudformation', 'describe-change-set', '--change-set-name', plan['change_set_arn'])
    validate_changes(described['Changes'])
    if (described['Changes'] != plan['changes'] or
            described['ExecutionStatus'] != 'AVAILABLE' or
            described['StackId'] != plan['stack_id']):
        raise RuntimeError('reviewed broker update changed or cannot execute')
    aws('cloudformation', 'execute-change-set', '--change-set-name', plan['change_set_arn'])
    aws('cloudformation', 'wait', 'stack-update-complete', '--stack-name', STACK)
    plan['status'] = 'DEPLOYED_PENDING_PROBE'
    Path(plan_path).write_text(json.dumps(plan, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({'status': plan['status'], 'source_commit': plan['source_commit']}))


def reconcile(plan_path):
    plan = json.loads(Path(plan_path).read_text(encoding='utf-8'))
    if plan.get('status') != 'PREPARED_NOT_EXECUTED':
        raise RuntimeError('broker update is not awaiting reconciliation')
    described = aws('cloudformation', 'describe-change-set', '--change-set-name', plan['change_set_arn'])
    if described.get('ExecutionStatus') != 'EXECUTE_COMPLETE':
        raise RuntimeError('broker update was not executed exactly as prepared')
    # The stack may now have a fresh version, so do not use _plan's old-version check.
    if (aws('sts', 'get-caller-identity')['Account'] != ACCOUNT or
            plan.get('source_commit') != source() or
            plan.get('template_sha256') != hashlib.sha256(TEMPLATE.read_bytes()).hexdigest() or
            plan.get('model_calls_authorized') != 0 or
            described.get('StackId') != plan.get('stack_id') or
            not isinstance(plan.get('artifact'), dict) or
            plan['artifact'].get('source_commit') != plan['source_commit'] or
            described['Changes'] != plan.get('changes')):
        raise RuntimeError('broker update reconciliation differs')
    validate_changes(plan['changes'])
    stack = _stack()
    if stack['StackId'] != plan['stack_id'] or _version(stack) == plan['previous_version']:
        raise RuntimeError('broker update did not publish a new version')
    plan['status'] = 'DEPLOYED_PENDING_PROBE'
    Path(plan_path).write_text(json.dumps(plan, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({'status': plan['status'], 'reconciled': True}))


def verify(plan_path):
    plan = _plan(plan_path, required_status='DEPLOYED_PENDING_PROBE')
    stack = _stack()
    if stack['StackId'] != plan['stack_id'] or _version(stack) == plan['previous_version']:
        raise RuntimeError('broker update did not publish a new version')
    arn = _version(stack)
    config = aws('lambda', 'get-function-configuration', '--function-name', arn)
    if (config.get('CodeSha256') != plan['artifact']['code_sha256'] or
            config.get('Role') != f'arn:aws:iam::{ACCOUNT}:role/{ROLE}' or
            config.get('Handler') != 'factory_runtime.acceptance_broker_lambda.handler' or
            config.get('Environment', {}).get('Variables') !=
            {'FACTORY_ACCEPTANCE_BROKER_ENABLED': 'false'}):
        raise RuntimeError('broker update code, role, handler or kill switch differs')
    attached = aws('iam', 'list-attached-role-policies', '--role-name', ROLE)
    inline = aws('iam', 'list-role-policies', '--role-name', ROLE)
    policy = aws('iam', 'get-role-policy', '--role-name', ROLE,
                 '--policy-name', 'canary-logs-only')['PolicyDocument']
    expected_resource = (f'arn:aws:logs:{REGION}:{ACCOUNT}:log-group:'
                         f'/aws/lambda/{FUNCTION}:*')
    if (attached.get('AttachedPolicies') != [] or
            inline.get('PolicyNames') != ['canary-logs-only'] or
            policy.get('Statement') != [{'Effect': 'Allow',
                'Action': ['logs:CreateLogStream', 'logs:PutLogEvents'],
                'Resource': expected_resource}]):
        raise RuntimeError('broker update gained additional IAM permissions')
    nonce = uuid.uuid4().hex
    event = {'kind': 'acceptance_broker_probe', 'source_commit': plan['source_commit'],
             'nonce': nonce, 'task_id': 'deterministic-text-fingerprint'}
    target = Path(plan_path).parent / 'acceptance-broker-update-probe.json'
    result = aws('lambda', 'invoke', '--function-name', arn,
                 '--invocation-type', 'RequestResponse', '--log-type', 'None',
                 '--cli-binary-format', 'raw-in-base64-out', '--payload',
                 json.dumps(event), str(target))
    if (result.get('FunctionError') or result.get('StatusCode') != 200 or
            result.get('ExecutedVersion') != arn.rsplit(':', 1)[1]):
        raise RuntimeError('broker update probe failed')
    proof = json.loads(target.read_text(encoding='utf-8'))
    expected = {'kind': 'acceptance_broker_probe_result',
                'source_commit': plan['source_commit'], 'nonce': nonce,
                'task_id': 'deterministic-text-fingerprint', 'broker_enabled': False,
                'provider_calls': 0, 'credentials_read': False, 'release_dispatched': False}
    if proof != expected:
        raise RuntimeError('broker update probe differs from model-free expectation')
    evidence = {'source_commit': plan['source_commit'], 'function_arn': arn,
                'previous_version': plan['previous_version'],
                'artifact_sha256': plan['artifact']['sha256'],
                'status': 'DISABLED_BROKER_COMPOSITION_VERIFIED', 'proof': proof}
    Path(plan_path).with_name('acceptance-broker-update-evidence.json').write_text(
        json.dumps(evidence, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(evidence, indent=2))


if __name__ == '__main__':
    if len(sys.argv) < 3:
        raise SystemExit('usage: prepare_acceptance_broker_update.py prepare PACKAGE PLAN | execute PLAN | reconcile PLAN | verify PLAN')
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
        raise SystemExit('invalid broker update command')
