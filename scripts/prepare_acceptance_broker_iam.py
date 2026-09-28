"""Stage and verify the two exact broker policies while the Lambda stays disabled.

The prepared change set may modify only the existing IAM role in place. No
Lambda code, version, environment, secret value, or provider request changes.
"""
from __future__ import annotations

import hashlib
import json
import sys
import uuid
from pathlib import Path

try:
    from .prepare_acceptance_broker_canary import (
        ACCOUNT, FUNCTION, REGION, ROLE, STACK, TEMPLATE, aws, source,
    )
except ImportError:
    from prepare_acceptance_broker_canary import (
        ACCOUNT, FUNCTION, REGION, ROLE, STACK, TEMPLATE, aws, source,
    )


BROKER_COMMIT = 'e3b6fbf9c2786ee6c400166c4649e5cb1bb20b5c'
POLICY_NAMES = (
    'tims-software-factory-acceptance-broker-records',
    'tims-software-factory-provider-broker-secret-reader',
)
POLICY_ARNS = tuple(f'arn:aws:iam::{ACCOUNT}:policy/{name}' for name in POLICY_NAMES)
ENVIRONMENT = {
    'FACTORY_ACCEPTANCE_BROKER_ENABLED': 'false',
    'FACTORY_ACCEPTANCE_ACTIVATION_JSON': '',
    'FACTORY_OPENAI_SECRET_ARN': '',
}


def validate_template():
    template = json.loads(TEMPLATE.read_text(encoding='utf-8'))
    resources = template['Resources']
    role = resources['BrokerRole']['Properties']
    function = resources['BrokerFunction']['Properties']
    if (set(resources) != {'BrokerLogs', 'BrokerRole', 'BrokerFunction', 'BrokerVersion'} or
            role.get('ManagedPolicyArns') != list(POLICY_ARNS) or
            [p.get('PolicyName') for p in role.get('Policies', [])] != ['canary-logs-only'] or
            function['Environment']['Variables'] != {
                'FACTORY_ACCEPTANCE_BROKER_ENABLED': 'false',
                'FACTORY_ACCEPTANCE_ACTIVATION_JSON': {'Ref': 'BrokerActivationJson'},
                'FACTORY_OPENAI_SECRET_ARN': {'Ref': 'ProviderSecretArn'}} or
            any(template['Parameters'][key].get('Default') != '' for key in
                ('BrokerActivationJson', 'ProviderSecretArn'))):
        raise RuntimeError('broker IAM template differs from disabled two-policy stage')


def validate_changes(changes):
    if (len(changes) != 1 or
            changes[0]['ResourceChange'].get('LogicalResourceId') != 'BrokerRole' or
            changes[0]['ResourceChange'].get('Action') != 'Modify' or
            changes[0]['ResourceChange'].get('Replacement') != 'False'):
        raise RuntimeError('broker IAM change set must modify only the role in place')


def _stack():
    stack = aws('cloudformation', 'describe-stacks', '--stack-name', STACK)['Stacks'][0]
    if stack['StackStatus'] not in {'CREATE_COMPLETE', 'UPDATE_COMPLETE'}:
        raise RuntimeError('broker stack is not ready')
    return stack


def _version(stack):
    outputs = {entry['OutputKey']: entry['OutputValue'] for entry in stack['Outputs']}
    return outputs['BrokerVersionArn']


def _configuration(arn):
    config = aws('lambda', 'get-function-configuration', '--function-name', arn)
    if (config.get('FunctionArn') != arn or
            config.get('Role') != f'arn:aws:iam::{ACCOUNT}:role/{ROLE}' or
            config.get('Environment', {}).get('Variables') != ENVIRONMENT or
            config.get('Handler') != 'factory_runtime.acceptance_broker_lambda.handler' or
            config.get('State') != 'Active'):
        raise RuntimeError('broker version is not the disabled deployment')
    return config


def _plan(path, status):
    plan = json.loads(Path(path).read_text(encoding='utf-8'))
    validate_template()
    if (aws('sts', 'get-caller-identity')['Account'] != ACCOUNT or
            plan.get('source_commit') != source() or
            plan.get('template_sha256') != hashlib.sha256(TEMPLATE.read_bytes()).hexdigest() or
            plan.get('status') != status or plan.get('model_calls_authorized') != 0 or
            plan.get('previous_version') != _version(_stack())):
        raise RuntimeError('broker IAM plan differs from exact disabled deployment')
    validate_changes(plan['changes'])
    return plan


def _policy_document(arn):
    policy = aws('iam', 'get-policy', '--policy-arn', arn)['Policy']
    if (policy.get('Arn') != arn or policy.get('AttachmentCount') not in (0, 1)):
        raise RuntimeError('broker IAM policy identity or attachments differ')
    return aws('iam', 'get-policy-version', '--policy-arn', arn,
               '--version-id', policy['DefaultVersionId'])['PolicyVersion']['Document']


def _assert_policy_documents():
    budget_arn = f'arn:aws:dynamodb:{REGION}:{ACCOUNT}:table/tims-factory-acceptance-budget'
    claim_arn = f'arn:aws:dynamodb:{REGION}:{ACCOUNT}:table/tims-factory-acceptance-broker-claims'
    secret = aws('secretsmanager', 'describe-secret', '--secret-id',
                 'tims-software-factory/provider/openai/acceptance')
    secret_arn = secret.get('ARN')
    if (secret.get('Name') != 'tims-software-factory/provider/openai/acceptance' or
            not isinstance(secret_arn, str) or
            not secret_arn.startswith(f'arn:aws:secretsmanager:{REGION}:{ACCOUNT}:secret:'
                                      'tims-software-factory/provider/openai/acceptance-') or
            secret.get('DeletedDate') is not None):
        raise RuntimeError('broker provider secret identity differs')
    kms_arn = aws('kms', 'describe-key', '--key-id',
                  'alias/tims-software-factory-provider-credentials')['KeyMetadata']['Arn']
    expected = (
        [
            {'Sid': 'ReadExactAcceptanceReservations', 'Effect': 'Allow',
             'Action': 'dynamodb:GetItem', 'Resource': budget_arn,
             'Condition': {'ForAllValues:StringLike': {'dynamodb:LeadingKeys': 'ACTIVATION#*'}}},
            {'Sid': 'ClaimExactAcceptanceDispatch', 'Effect': 'Allow',
             'Action': ['dynamodb:GetItem', 'dynamodb:PutItem', 'dynamodb:UpdateItem'],
             'Resource': claim_arn,
             'Condition': {'ForAllValues:StringLike': {'dynamodb:LeadingKeys': 'ACTIVATION#*'}}},
        ],
        [
            {'Sid': 'ReadExactCurrentProviderSecret', 'Effect': 'Allow',
             'Action': 'secretsmanager:GetSecretValue', 'Resource': secret_arn,
             'Condition': {'ForAnyValue:StringEquals': {'secretsmanager:VersionStage': 'AWSCURRENT'}}},
            {'Sid': 'DecryptOnlyThroughExactSecretsManagerRegion', 'Effect': 'Allow',
             'Action': 'kms:Decrypt', 'Resource': kms_arn,
             'Condition': {'StringEquals': {'kms:ViaService': f'secretsmanager.{REGION}.amazonaws.com'}}},
        ],
    )
    # IAM may return singleton Action/Resource/condition values as either a
    # scalar or a one-element array; compare canonicalized values exactly.
    def normalize(value):
        if isinstance(value, list):
            items = [normalize(item) for item in value]
            return items[0] if len(items) == 1 else items
        if isinstance(value, dict):
            return {key: normalize(item) for key, item in value.items()}
        return value
    for arn, statements in zip(POLICY_ARNS, expected):
        document = _policy_document(arn)
        if (document.get('Version') != '2012-10-17' or
                normalize(document.get('Statement')) != normalize(statements)):
            raise RuntimeError('broker managed policy differs from reviewed least privilege')


def prepare(path):
    commit = source()
    validate_template()
    if aws('sts', 'get-caller-identity')['Account'] != ACCOUNT:
        raise RuntimeError('wrong AWS account')
    stack = _stack()
    version = _version(stack)
    if not version.endswith(':3') or _configuration(version).get('CodeSha256') is None:
        raise RuntimeError('expected disabled broker version 3 is missing')
    if aws('iam', 'list-attached-role-policies', '--role-name', ROLE)['AttachedPolicies'] != []:
        raise RuntimeError('broker role already has managed policies')
    _assert_policy_documents()
    parameters = [{'ParameterKey': key, 'UsePreviousValue': True} for key in
                  ('ArtifactBucket', 'ArtifactKey', 'ArtifactVersion', 'CodeSha256',
                   'BrokerActivationJson', 'ProviderSecretArn')]
    aws('cloudformation', 'validate-template', '--template-body', 'file://' + str(TEMPLATE))
    name = 'broker-iam-' + commit[:12] + '-' + uuid.uuid4().hex[:8]
    created = aws('cloudformation', 'create-change-set', '--stack-name', STACK,
                  '--change-set-name', name, '--change-set-type', 'UPDATE',
                  '--template-body', 'file://' + str(TEMPLATE), '--parameters',
                  json.dumps(parameters), '--capabilities', 'CAPABILITY_NAMED_IAM')
    arn = created['Id']
    aws('cloudformation', 'wait', 'change-set-create-complete', '--change-set-name', arn)
    described = aws('cloudformation', 'describe-change-set', '--change-set-name', arn)
    validate_changes(described['Changes'])
    plan = {'source_commit': commit, 'change_set_arn': arn,
            'stack_id': stack['StackId'], 'previous_version': version,
            'code_sha256': _configuration(version)['CodeSha256'],
            'template_sha256': hashlib.sha256(TEMPLATE.read_bytes()).hexdigest(),
            'changes': described['Changes'], 'status': 'PREPARED_NOT_EXECUTED',
            'model_calls_authorized': 0}
    Path(path).write_text(json.dumps(plan, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({'status': plan['status'], 'source_commit': commit,
                      'resources': ['BrokerRole'], 'version': version}))


def execute(path):
    plan = _plan(path, 'PREPARED_NOT_EXECUTED')
    described = aws('cloudformation', 'describe-change-set',
                    '--change-set-name', plan['change_set_arn'])
    if (described.get('StackId') != plan['stack_id'] or
            described.get('ExecutionStatus') != 'AVAILABLE' or
            described.get('Changes') != plan['changes'] or
            _configuration(plan['previous_version']).get('CodeSha256') != plan['code_sha256']):
        raise RuntimeError('broker IAM change set or Lambda changed before execution')
    _assert_policy_documents()
    aws('cloudformation', 'execute-change-set', '--change-set-name', plan['change_set_arn'])
    aws('cloudformation', 'wait', 'stack-update-complete', '--stack-name', STACK)
    plan['status'] = 'DEPLOYED_PENDING_PROBE'
    Path(path).write_text(json.dumps(plan, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({'status': plan['status'], 'source_commit': plan['source_commit']}))


def reconcile(path):
    plan = _plan(path, 'PREPARED_NOT_EXECUTED')
    described = aws('cloudformation', 'describe-change-set',
                    '--change-set-name', plan['change_set_arn'])
    if (described.get('ExecutionStatus') != 'EXECUTE_COMPLETE' or
            described.get('StackId') != plan['stack_id'] or
            described.get('Changes') != plan['changes'] or
            _stack()['StackId'] != plan['stack_id'] or
            _configuration(plan['previous_version']).get('CodeSha256') != plan['code_sha256']):
        raise RuntimeError('broker IAM reconciliation differs from prepared change set')
    plan['status'] = 'DEPLOYED_PENDING_PROBE'
    Path(path).write_text(json.dumps(plan, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({'status': plan['status'], 'reconciled': True}))


def verify(path):
    plan = _plan(path, 'DEPLOYED_PENDING_PROBE')
    if (_stack()['StackId'] != plan['stack_id'] or
            _configuration(plan['previous_version']).get('CodeSha256') != plan['code_sha256']):
        raise RuntimeError('broker version, code, or stack differs')
    attached = aws('iam', 'list-attached-role-policies', '--role-name', ROLE)['AttachedPolicies']
    if {(item['PolicyName'], item['PolicyArn']) for item in attached} != set(zip(POLICY_NAMES, POLICY_ARNS)):
        raise RuntimeError('broker role policies differ from exact two-policy stage')
    _assert_policy_documents()
    nonce = uuid.uuid4().hex
    event = {'kind': 'acceptance_broker_probe', 'source_commit': BROKER_COMMIT,
             'nonce': nonce, 'task_id': 'deterministic-text-fingerprint'}
    response_file = Path(path).with_name('acceptance-broker-iam-probe.json')
    result = aws('lambda', 'invoke', '--function-name', plan['previous_version'],
                 '--invocation-type', 'RequestResponse', '--log-type', 'None',
                 '--cli-binary-format', 'raw-in-base64-out', '--payload', json.dumps(event),
                 str(response_file))
    proof = json.loads(response_file.read_text(encoding='utf-8'))
    if (result.get('FunctionError') or result.get('StatusCode') != 200 or
            result.get('ExecutedVersion') != '3' or
            proof != {'kind': 'acceptance_broker_probe_result',
                      'source_commit': BROKER_COMMIT, 'nonce': nonce,
                      'task_id': 'deterministic-text-fingerprint',
                      'broker_enabled': False, 'provider_calls': 0,
                      'credentials_read': False, 'release_dispatched': False}):
        raise RuntimeError('broker IAM probe differs from disabled expectation')
    evidence = {'status': 'DISABLED_BROKER_IAM_VERIFIED',
                'source_commit': plan['source_commit'], 'function_arn': plan['previous_version'],
                'attached_policies': list(POLICY_ARNS), 'proof': proof}
    Path(path).with_name('acceptance-broker-iam-evidence.json').write_text(
        json.dumps(evidence, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(evidence))


if __name__ == '__main__':
    if len(sys.argv) != 3:
        raise SystemExit('usage: prepare_acceptance_broker_iam.py prepare|execute|reconcile|verify PLAN')
    actions = {'prepare': prepare, 'execute': execute,
               'reconcile': reconcile, 'verify': verify}
    if sys.argv[1] not in actions:
        raise SystemExit('invalid broker IAM command')
    actions[sys.argv[1]](sys.argv[2])
