"""Read-only preflight for the two disabled receipt publisher identities.

No receipt is published and no IAM policy is attached by this script.
"""
from __future__ import annotations

import json
import hashlib
import subprocess
import sys
from pathlib import Path

ACCOUNT = '666730517561'
REGION = 'ca-central-1'
STACK = 'tims-factory-signing'
BUCKET = f'tims-software-factory-{ACCOUNT}-{REGION}'
TEMPLATE = Path(__file__).resolve().parents[1] / 'infra/signing/keys.cloudformation.json'
ROLES = {
    'owner': ('OwnerRole', 'tims-factory-signing-owner',
              'tims-software-factory-owner-receipt-writer'),
    'reviewer': ('InspectorRole', 'tims-factory-signing-inspector',
                 'tims-software-factory-reviewer-receipt-writer'),
}


def aws(service, action, *args):
    result = subprocess.run(['aws', service, action, *args, '--region', REGION,
                             '--output', 'json', '--no-cli-pager'],
                            capture_output=True, text=True,
                            timeout=900 if action == 'wait' else 60, check=True)
    return json.loads(result.stdout or '{}')


def _document(value):
    if isinstance(value, str):
        return json.loads(value)
    return value


def inspect(*, template_path: Path = TEMPLATE, expected_attached: bool = False):
    if aws('sts', 'get-caller-identity').get('Account') != ACCOUNT:
        raise RuntimeError('wrong AWS account')
    stack = aws('cloudformation', 'describe-stacks', '--stack-name', STACK)['Stacks'][0]
    if stack.get('StackStatus') not in {'CREATE_COMPLETE', 'UPDATE_COMPLETE'}:
        raise RuntimeError('signing stack is not stable')
    params = {p['ParameterKey']: p['ParameterValue'] for p in stack.get('Parameters', [])}
    if params.get('EnableRoleExecutionTrust') not in {'true', 'false'}:
        raise RuntimeError('inspector execution trust parameter is unknown')
    template = json.loads(template_path.read_text(encoding='utf-8'))
    deployed = _document(aws('cloudformation', 'get-template', '--stack-name', STACK)['TemplateBody'])
    if deployed != template:
        raise RuntimeError('deployed signing template differs from reviewed source')
    resources = aws('cloudformation', 'describe-stack-resources', '--stack-name', STACK)['StackResources']
    physical = {entry['LogicalResourceId']: entry['PhysicalResourceId'] for entry in resources}
    result = {}
    for kind, (logical, role_name, policy_name) in ROLES.items():
        if physical.get(logical) != role_name:
            raise RuntimeError(f'{kind} signing role differs from stack')
        role = aws('iam', 'get-role', '--role-name', role_name)['Role']
        if role.get('Arn') != f'arn:aws:iam::{ACCOUNT}:role/{role_name}':
            raise RuntimeError(f'{kind} signing role identity differs')
        expected = template['Resources'][logical]['Properties']['AssumeRolePolicyDocument']['Statement'][0]
        statements = _document(role['AssumeRolePolicyDocument'])['Statement']
        if isinstance(statements, dict):
            statements = [statements]
        permitted = [expected]
        if kind == 'reviewer' and params['EnableRoleExecutionTrust'] == 'true':
            permitted.append(template['Resources'][logical]['Properties']
                             ['AssumeRolePolicyDocument']['Statement'][1]['Fn::If'][1])
        if statements != permitted:
            raise RuntimeError(f'{kind} signing role trust differs')
        attached = aws('iam', 'list-attached-role-policies', '--role-name', role_name)
        inline = aws('iam', 'list-role-policies', '--role-name', role_name)
        expected_binding = ([{'PolicyName': policy_name, 'PolicyArn':
                             f'arn:aws:iam::{ACCOUNT}:policy/{policy_name}'}]
                            if expected_attached else [])
        if (attached.get('IsTruncated') or attached.get('AttachedPolicies') != expected_binding or
                inline.get('IsTruncated') or inline.get('PolicyNames') != ['OwnSigningKeyOnly']):
            raise RuntimeError(f'{kind} signer has unexpected policy attachments')
        arn = f'arn:aws:iam::{ACCOUNT}:policy/{policy_name}'
        policy = aws('iam', 'get-policy', '--policy-arn', arn)['Policy']
        if (policy.get('Arn') != arn or policy.get('AttachmentCount') != int(expected_attached) or
                not policy.get('DefaultVersionId')):
            raise RuntimeError(f'{kind} receipt policy is missing or already attached')
        document = _document(aws('iam', 'get-policy-version', '--policy-arn', arn,
                                 '--version-id', policy['DefaultVersionId'])['PolicyVersion']['Document'])
        expected_policy = {'Version': '2012-10-17', 'Statement': [{
            'Sid': 'WriteOwnerReceiptOnly' if kind == 'owner' else 'WriteReviewerReceiptOnly',
            'Effect': 'Allow', 'Action': 's3:PutObject',
            'Resource': f'arn:aws:s3:::{BUCKET}/factory-scope-receipts/*/{kind}.json',
            'Condition': {'StringEquals': {'s3:x-amz-server-side-encryption': 'AES256'}}}]}
        if document != expected_policy:
            raise RuntimeError(f'{kind} receipt policy differs from least privilege')
        result[kind] = {'role_arn': role['Arn'], 'policy_arn': arn,
                        'trust': 'EXACT', 'policy': 'EXACT_ATTACHED' if expected_attached
                        else 'EXACT_UNATTACHED'}
    return {'status': 'RECEIPT_WRITER_IAM_ATTACHED_VERIFIED' if expected_attached else
            'RECEIPT_WRITER_IDENTITIES_READY_FOR_REVIEW_NOT_ATTACHED',
            'account': ACCOUNT, 'region': REGION, 'signing_stack': STACK,
            'template_sha256': hashlib.sha256(template_path.read_bytes()).hexdigest(),
            'inspector_execution_trust_enabled': params['EnableRoleExecutionTrust'] == 'true',
            'identities': result, 'receipts_published': 0, 'model_calls': 0}


if __name__ == '__main__':
    if len(sys.argv) != 1:
        raise SystemExit('usage: inspect_receipt_writer_iam.py')
    print(json.dumps(inspect(), indent=2))
