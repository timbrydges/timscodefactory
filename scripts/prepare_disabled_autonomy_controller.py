"""Stage, deploy, reconcile and verify the inert acceptance controller alias."""
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


STACK = 'tims-factory-autonomy-controller-disabled'
TEMPLATE = ROOT / 'infra/acceptance/controller-disabled.cloudformation.json'
FUNCTION = 'tims-software-factory-autonomy-controller'
ROLE = 'tims-software-factory-autonomy-controller-disabled'
ALIAS = f'arn:aws:lambda:{REGION}:{ACCOUNT}:function:{FUNCTION}:acceptance'
RESOURCES = {'ControllerLogs', 'ControllerRole', 'ControllerFunction',
             'ControllerVersion', 'AcceptanceAlias'}


def validate_template():
    template = json.loads(TEMPLATE.read_text(encoding='utf-8'))
    resources = template['Resources']
    role = resources['ControllerRole']['Properties']
    function = resources['ControllerFunction']['Properties']
    alias = resources['AcceptanceAlias']['Properties']
    if (set(resources) != RESOURCES or role.get('ManagedPolicyArns') or
            role.get('RoleName') != ROLE or function.get('FunctionName') != FUNCTION or
            function.get('Role') != {'Fn::GetAtt': ['ControllerRole', 'Arn']} or
            function.get('Handler') != 'factory_runtime.autonomy_controller_lambda.handler' or
            function.get('Environment') != {
                'Variables': {'FACTORY_AUTONOMY_CONTROLLER_ENABLED': 'false'}} or
            role.get('Policies') != [{'PolicyName': 'canary-logs-only',
                'PolicyDocument': {'Version': '2012-10-17', 'Statement': [{
                    'Effect': 'Allow', 'Action': ['logs:CreateLogStream', 'logs:PutLogEvents'],
                    'Resource': f'arn:aws:logs:{REGION}:{ACCOUNT}:log-group:/aws/lambda/{FUNCTION}:*'}]}}] or
            alias != {'Name': 'acceptance', 'FunctionName': {'Ref': 'ControllerFunction'},
                      'FunctionVersion': {'Fn::GetAtt': ['ControllerVersion', 'Version']}}):
        raise RuntimeError('disabled controller template differs from reviewed boundary')
    return hashlib.sha256(TEMPLATE.read_bytes()).hexdigest()


def validate_changes(changes):
    items = [entry['ResourceChange'] for entry in changes]
    if (len(items) != len(RESOURCES) or
            {item.get('LogicalResourceId') for item in items} != RESOURCES or
            any(item.get('Action') != 'Add' for item in items)):
        raise RuntimeError('controller change set must add only its five disabled resources')


def checked_plan(path, status):
    plan = json.loads(Path(path).read_text(encoding='utf-8'))
    if (plan.get('status') != status or plan.get('source_commit') != source() or
            plan.get('template_sha256') != validate_template() or
            plan.get('model_calls_authorized') != 0 or
            plan.get('artifact', {}).get('source_commit') != plan.get('source_commit') or
            aws('sts', 'get-caller-identity').get('Account') != ACCOUNT):
        raise RuntimeError('controller deployment plan differs from reviewed source/account')
    validate_changes(plan['changes'])
    return plan


def prepare(package, path):
    commit = source()
    digest = validate_template()
    if aws('sts', 'get-caller-identity').get('Account') != ACCOUNT:
        raise RuntimeError('wrong AWS account')
    package = Path(package).resolve()
    manifest = json.loads(package.with_suffix('.json').read_text(encoding='utf-8'))
    if (manifest.get('source_commit') != commit or
            manifest.get('sha256') != hashlib.sha256(package.read_bytes()).hexdigest()):
        raise RuntimeError('controller package differs from exact clean checkout')
    key = f'factory-autonomy-controller-packages/{commit}/{manifest["sha256"]}.zip'
    upload = aws('s3api', 'put-object', '--bucket', BUCKET, '--key', key,
                 '--body', str(package), '--checksum-algorithm', 'SHA256',
                 '--checksum-sha256', manifest['code_sha256'])
    version = upload.get('VersionId')
    if not version or version == 'null':
        raise RuntimeError('versioned controller artifact required')
    parameters = [{'ParameterKey': k, 'ParameterValue': v} for k, v in {
        'ArtifactBucket': BUCKET, 'ArtifactKey': key, 'ArtifactVersion': version,
        'CodeSha256': manifest['code_sha256']}.items()]
    aws('cloudformation', 'validate-template', '--template-body', 'file://' + str(TEMPLATE))
    name = 'disabled-controller-' + commit[:12] + '-' + uuid.uuid4().hex[:8]
    created = aws('cloudformation', 'create-change-set', '--stack-name', STACK,
                  '--change-set-name', name, '--change-set-type', 'CREATE',
                  '--template-body', 'file://' + str(TEMPLATE), '--parameters',
                  json.dumps(parameters), '--capabilities', 'CAPABILITY_NAMED_IAM')
    arn = created['Id']
    aws('cloudformation', 'wait', 'change-set-create-complete', '--change-set-name', arn)
    described = aws('cloudformation', 'describe-change-set', '--change-set-name', arn)
    validate_changes(described['Changes'])
    plan = {'status': 'PREPARED_NOT_EXECUTED', 'source_commit': commit,
            'artifact': manifest, 'template_sha256': digest, 'change_set_arn': arn,
            'stack_id': described['StackId'], 'changes': described['Changes'],
            'model_calls_authorized': 0}
    Path(path).write_text(json.dumps(plan, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({'status': plan['status'], 'source_commit': commit,
                      'resources': sorted(RESOURCES)}))


def execute(path):
    plan = checked_plan(path, 'PREPARED_NOT_EXECUTED')
    described = aws('cloudformation', 'describe-change-set',
                    '--change-set-name', plan['change_set_arn'])
    validate_changes(described['Changes'])
    if (described.get('ExecutionStatus') != 'AVAILABLE' or
            described.get('StackId') != plan['stack_id'] or
            described['Changes'] != plan['changes']):
        raise RuntimeError('reviewed controller change set changed or is unavailable')
    aws('cloudformation', 'execute-change-set', '--change-set-name', plan['change_set_arn'])
    aws('cloudformation', 'wait', 'stack-create-complete', '--stack-name', STACK)
    plan['status'] = 'DEPLOYED_PENDING_PROBE'
    Path(path).write_text(json.dumps(plan, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({'status': plan['status'], 'source_commit': plan['source_commit']}))


def reconcile(path):
    plan = checked_plan(path, 'PREPARED_NOT_EXECUTED')
    described = aws('cloudformation', 'describe-change-set',
                    '--change-set-name', plan['change_set_arn'])
    validate_changes(described['Changes'])
    stack = aws('cloudformation', 'describe-stacks', '--stack-name', STACK)['Stacks'][0]
    if (described.get('ExecutionStatus') != 'EXECUTE_COMPLETE' or
            described.get('StackId') != plan['stack_id'] or
            described['Changes'] != plan['changes'] or
            stack.get('StackId') != plan['stack_id'] or
            stack.get('StackStatus') != 'CREATE_COMPLETE'):
        raise RuntimeError('controller change set has not completed exactly as prepared')
    plan['status'] = 'DEPLOYED_PENDING_PROBE'
    Path(path).write_text(json.dumps(plan, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({'status': plan['status'], 'reconciled': True}))


def verify(path):
    plan = checked_plan(path, 'DEPLOYED_PENDING_PROBE')
    stack = aws('cloudformation', 'describe-stacks', '--stack-name', STACK)['Stacks'][0]
    if stack.get('StackId') != plan['stack_id'] or stack.get('StackStatus') != 'CREATE_COMPLETE':
        raise RuntimeError('controller stack differs from prepared deployment')
    outputs = {item['OutputKey']: item['OutputValue'] for item in stack['Outputs']}
    version = outputs.get('ControllerVersionArn')
    prefix = f'arn:aws:lambda:{REGION}:{ACCOUNT}:function:{FUNCTION}:'
    if (outputs.get('AcceptanceAliasArn') != ALIAS or
            not isinstance(version, str) or not version.startswith(prefix) or
            not re.fullmatch(r'[1-9][0-9]*', version[len(prefix):])):
        raise RuntimeError('controller alias or immutable version differs')
    alias = aws('lambda', 'get-alias', '--function-name', FUNCTION, '--name', 'acceptance')
    config = aws('lambda', 'get-function-configuration', '--function-name', version)
    if (alias.get('AliasArn') != ALIAS or alias.get('FunctionVersion') != version.rsplit(':', 1)[1] or
            alias.get('RoutingConfig', {}).get('AdditionalVersionWeights') or
            config.get('FunctionArn') != version or
            config.get('CodeSha256') != plan['artifact']['code_sha256'] or
            config.get('Role') != f'arn:aws:iam::{ACCOUNT}:role/{ROLE}' or
            config.get('Handler') != 'factory_runtime.autonomy_controller_lambda.handler' or
            config.get('Environment', {}).get('Variables') !=
                {'FACTORY_AUTONOMY_CONTROLLER_ENABLED': 'false'}):
        raise RuntimeError('controller alias, code, role or kill switch differs')
    attached = aws('iam', 'list-attached-role-policies', '--role-name', ROLE)
    inline = aws('iam', 'list-role-policies', '--role-name', ROLE)
    policy = aws('iam', 'get-role-policy', '--role-name', ROLE,
                 '--policy-name', 'canary-logs-only')['PolicyDocument']
    expected = [{'Effect': 'Allow', 'Action': ['logs:CreateLogStream', 'logs:PutLogEvents'],
                 'Resource': f'arn:aws:logs:{REGION}:{ACCOUNT}:log-group:/aws/lambda/{FUNCTION}:*'}]
    if (attached.get('AttachedPolicies') != [] or inline.get('PolicyNames') != ['canary-logs-only'] or
            policy.get('Statement') != expected):
        raise RuntimeError('controller role gained permissions')
    nonce = uuid.uuid4().hex
    event = {'kind': 'disabled_controller_probe', 'source_commit': plan['source_commit'],
             'nonce': nonce, 'task_id': 'deterministic-text-fingerprint'}
    target = Path(path).parent / 'disabled-controller-probe.json'
    response = aws('lambda', 'invoke', '--function-name', ALIAS,
                   '--invocation-type', 'RequestResponse', '--log-type', 'None',
                   '--cli-binary-format', 'raw-in-base64-out', '--payload', json.dumps(event), str(target))
    if (response.get('FunctionError') or response.get('StatusCode') != 200 or
            response.get('ExecutedVersion') != version.rsplit(':', 1)[1]):
        raise RuntimeError('disabled controller probe invocation failed')
    proof = json.loads(target.read_text(encoding='utf-8'))
    expected_proof = {'kind': 'disabled_controller_probe_result',
                      'source_commit': plan['source_commit'], 'nonce': nonce,
                      'task_id': 'deterministic-text-fingerprint',
                      'controller_enabled': False, 'schedule_enabled': False,
                      'model_calls': 0, 'release_dispatched': False}
    if proof != expected_proof:
        raise RuntimeError('controller response differed from model-free probe')
    evidence = {'status': 'DISABLED_AUTONOMY_CONTROLLER_ALIAS_VERIFIED',
                'source_commit': plan['source_commit'], 'alias_arn': ALIAS,
                'version_arn': version, 'proof': proof}
    Path(path).with_name('disabled-controller-evidence.json').write_text(
        json.dumps(evidence, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(evidence, indent=2))


if __name__ == '__main__':
    if len(sys.argv) == 4 and sys.argv[1] == 'prepare':
        prepare(sys.argv[2], sys.argv[3])
    elif len(sys.argv) == 3 and sys.argv[1] in {'execute', 'reconcile', 'verify'}:
        {'execute': execute, 'reconcile': reconcile, 'verify': verify}[sys.argv[1]](sys.argv[2])
    else:
        raise SystemExit('use prepare PACKAGE PLAN | execute PLAN | reconcile PLAN | verify PLAN')
