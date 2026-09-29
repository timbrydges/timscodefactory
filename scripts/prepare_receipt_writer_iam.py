"""Guard and verify the exact two signing-role receipt policy attachments.

No approval receipt is published. IAM simulation checks each permitted write
and denies cross-writer, unencrypted, and read requests without writing S3.
"""
from __future__ import annotations

import hashlib
import json
import re
import subprocess
import sys
import tempfile
import uuid
from pathlib import Path

from inspect_receipt_writer_iam import ACCOUNT, BUCKET, REGION, ROLES, STACK, TEMPLATE, aws, inspect

ROOT = TEMPLATE.parents[2]
BASE_COMMIT = '58e4e277a809ff7e142a4bedb1d1bd438d03fdd0'


def source():
    commit = subprocess.check_output(['git', '-C', str(ROOT), 'rev-parse', 'HEAD'], text=True).strip()
    dirty = subprocess.check_output(['git', '-C', str(ROOT), 'status', '--porcelain'], text=True)
    if dirty or not re.fullmatch(r'[a-f0-9]{40}', commit):
        raise RuntimeError('clean exact receipt IAM checkout required')
    return commit


def base_preflight():
    raw = subprocess.check_output(['git', '-C', str(ROOT), 'show',
                                   BASE_COMMIT + ':infra/signing/keys.cloudformation.json'])
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / 'deployed-before.json'
        path.write_bytes(raw)
        return inspect(template_path=path)


def validate_template():
    old = json.loads(subprocess.check_output(['git', '-C', str(ROOT), 'show',
        BASE_COMMIT + ':infra/signing/keys.cloudformation.json']))
    new = json.loads(TEMPLATE.read_text(encoding='utf-8'))
    for _, (logical, _, policy_name) in ROLES.items():
        role = new['Resources'][logical]['Properties']
        expected_arn = f'arn:aws:iam::{ACCOUNT}:policy/{policy_name}'
        if role.get('ManagedPolicyArns') != [expected_arn]:
            raise RuntimeError('receipt role policy attachment differs')
        del role['ManagedPolicyArns']
    if new != old:
        raise RuntimeError('receipt IAM template changes beyond two policy attachments')


def validate_changes(changes):
    if len(changes) != 2:
        raise RuntimeError('receipt IAM change set must contain only two roles')
    resources = {entry['ResourceChange']['LogicalResourceId']: entry['ResourceChange']
                 for entry in changes}
    if set(resources) != {'OwnerRole', 'InspectorRole'}:
        raise RuntimeError('receipt IAM change set touched unexpected resources')
    for change in resources.values():
        if (change.get('ResourceType') != 'AWS::IAM::Role' or
                change.get('Action') != 'Modify' or
                change.get('Replacement') != 'False' or
                change.get('Scope') != ['Properties']):
            raise RuntimeError('receipt IAM change set must modify roles in place')
        for detail in change.get('Details', []):
            if detail.get('Target', {}).get('Name') != 'ManagedPolicyArns':
                raise RuntimeError('receipt IAM change set changes more than managed policies')


def _stack():
    stack = aws('cloudformation', 'describe-stacks', '--stack-name', STACK)['Stacks'][0]
    if stack.get('StackStatus') not in {'CREATE_COMPLETE', 'UPDATE_COMPLETE'}:
        raise RuntimeError('signing stack is not ready')
    return stack


def _plan(path, status):
    plan = json.loads(Path(path).read_text(encoding='utf-8'))
    if (aws('sts', 'get-caller-identity').get('Account') != ACCOUNT or
            plan.get('source_commit') != source() or plan.get('status') != status or
            plan.get('template_sha256') != hashlib.sha256(TEMPLATE.read_bytes()).hexdigest() or
            plan.get('model_calls_authorized') != 0 or plan.get('receipts_authorized') != 0 or
            plan.get('stack_id') != _stack()['StackId']):
        raise RuntimeError('receipt IAM plan differs from reviewed source')
    validate_template()
    validate_changes(plan['changes'])
    return plan


def prepare(plan_path):
    commit = source()
    validate_template()
    before = _stack()
    base_preflight()
    aws('cloudformation', 'validate-template', '--template-body', 'file://' + str(TEMPLATE))
    name = 'receipt-writers-' + commit[:12] + '-' + uuid.uuid4().hex[:8]
    created = aws('cloudformation', 'create-change-set', '--stack-name', STACK,
                  '--change-set-name', name, '--change-set-type', 'UPDATE',
                  '--template-body', 'file://' + str(TEMPLATE),
                  '--parameters', 'ParameterKey=EnableRoleExecutionTrust,UsePreviousValue=true',
                  '--capabilities', 'CAPABILITY_NAMED_IAM')
    arn = created['Id']
    aws('cloudformation', 'wait', 'change-set-create-complete', '--change-set-name', arn)
    described = aws('cloudformation', 'describe-change-set', '--change-set-name', arn)
    validate_changes(described['Changes'])
    if described['StackId'] != before['StackId'] or described['ExecutionStatus'] != 'AVAILABLE':
        raise RuntimeError('receipt IAM change set differs from signing stack')
    plan = {'source_commit': commit, 'template_sha256': hashlib.sha256(TEMPLATE.read_bytes()).hexdigest(),
            'stack_id': before['StackId'], 'change_set_arn': arn, 'changes': described['Changes'],
            'status': 'PREPARED_NOT_EXECUTED', 'receipts_authorized': 0,
            'model_calls_authorized': 0}
    Path(plan_path).write_text(json.dumps(plan, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({'status': plan['status'], 'source_commit': commit,
                      'resources': ['OwnerRole', 'InspectorRole'], 'receipts_authorized': 0}))


def execute(plan_path):
    plan = _plan(plan_path, 'PREPARED_NOT_EXECUTED')
    base_preflight()
    described = aws('cloudformation', 'describe-change-set', '--change-set-name', plan['change_set_arn'])
    if (described.get('StackId') != plan['stack_id'] or
            described.get('ExecutionStatus') != 'AVAILABLE' or described.get('Changes') != plan['changes']):
        raise RuntimeError('receipt IAM change set differs from reviewed plan')
    aws('cloudformation', 'execute-change-set', '--change-set-name', plan['change_set_arn'])
    aws('cloudformation', 'wait', 'stack-update-complete', '--stack-name', STACK)
    plan['status'] = 'DEPLOYED_PENDING_VERIFICATION'
    Path(plan_path).write_text(json.dumps(plan, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({'status': plan['status'], 'source_commit': plan['source_commit']}))


def reconcile(plan_path):
    plan = _plan(plan_path, 'PREPARED_NOT_EXECUTED')
    described = aws('cloudformation', 'describe-change-set', '--change-set-name', plan['change_set_arn'])
    if (described.get('StackId') != plan['stack_id'] or
            described.get('ExecutionStatus') != 'EXECUTE_COMPLETE' or
            described.get('Changes') != plan['changes']):
        raise RuntimeError('receipt IAM change set was not executed as reviewed')
    inspect(expected_attached=True)
    plan['status'] = 'DEPLOYED_PENDING_VERIFICATION'
    Path(plan_path).write_text(json.dumps(plan, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({'status': plan['status'], 'reconciled': True}))


def _decision(role, action, resource, *, encrypted):
    args = ['--policy-source-arn', role, '--action-names', action,
            '--resource-arns', resource]
    if encrypted:
        args += ['--context-entries',
                 'ContextKeyName=s3:x-amz-server-side-encryption,ContextKeyValues=AES256,ContextKeyType=string']
    evaluation = aws('iam', 'simulate-principal-policy', *args)
    results = evaluation.get('EvaluationResults')
    if (evaluation.get('IsTruncated') or not isinstance(results, list) or len(results) != 1 or
            results[0].get('EvalActionName') != action or
            results[0].get('EvalResourceName') != resource):
        raise RuntimeError('receipt IAM simulation returned incomplete evidence')
    return results[0].get('EvalDecision')


def verify(plan_path):
    plan = _plan(plan_path, 'DEPLOYED_PENDING_VERIFICATION')
    bindings = inspect(expected_attached=True)
    digest = 'a' * 64
    for kind in ROLES:
        role = bindings['identities'][kind]['role_arn']
        own = f'arn:aws:s3:::{BUCKET}/factory-scope-receipts/{digest}/{kind}.json'
        other = ('reviewer' if kind == 'owner' else 'owner')
        cross = f'arn:aws:s3:::{BUCKET}/factory-scope-receipts/{digest}/{other}.json'
        decisions = (_decision(role, 's3:PutObject', own, encrypted=True),
                     _decision(role, 's3:PutObject', cross, encrypted=True),
                     _decision(role, 's3:PutObject', own, encrypted=False),
                     _decision(role, 's3:GetObject', own, encrypted=True))
        if decisions[0] != 'allowed' or any(value not in {'implicitDeny', 'explicitDeny'}
                                               for value in decisions[1:]):
            raise RuntimeError(f'{kind} receipt writer simulation differs')
    print(json.dumps({'status': 'RECEIPT_WRITER_IAM_ATTACHED_SIMULATED',
                      'source_commit': plan['source_commit'], 'roles': bindings['identities'],
                      'own_encrypted_put': 'allowed', 'cross_put': 'denied',
                      'unencrypted_put': 'denied', 'get_object': 'denied',
                      'receipts_published': 0, 'model_calls': 0}, indent=2))


if __name__ == '__main__':
    if len(sys.argv) != 3 or sys.argv[1] not in {'prepare', 'execute', 'reconcile', 'verify'}:
        raise SystemExit('usage: prepare_receipt_writer_iam.py prepare|execute|reconcile|verify PLAN')
    {'prepare': prepare, 'execute': execute, 'reconcile': reconcile, 'verify': verify}[sys.argv[1]](sys.argv[2])
