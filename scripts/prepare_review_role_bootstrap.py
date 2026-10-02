"""Render a reviewable twelve-resource bootstrap; no AWS calls or deployment."""
import json
import sys
from pathlib import Path

ACCOUNT = '666730517561'
REGION = 'ca-central-1'


def render():
    resources, outputs = {}, {}
    for label, role in [('Qa', 'qa'), ('Security', 'security')]:
        name = 'tims-factory-review-' + role
        role_arn = f'arn:aws:iam::{ACCOUNT}:role/{name}'
        key_arn = {'Fn::GetAtt': [label + 'Key', 'Arn']}
        resources[label + 'Key'] = {'Type': 'AWS::KMS::Key', 'DeletionPolicy': 'Retain',
            'UpdateReplacePolicy': 'Retain', 'Properties': {
                'Description': name + ' isolated signing; not yet enrolled',
                'KeySpec': 'ECC_NIST_EDWARDS25519', 'KeyUsage': 'SIGN_VERIFY',
                'MultiRegion': False, 'PendingWindowInDays': 30,
                'KeyPolicy': {'Version': '2012-10-17', 'Statement': [
                    {'Sid': 'OwnerAccountAdministration', 'Effect': 'Allow',
                     'Principal': {'AWS': f'arn:aws:iam::{ACCOUNT}:root'},
                     'Action': 'kms:*', 'Resource': '*'},
                    {'Sid': 'DenySigningOutsideExactRole', 'Effect': 'Deny', 'Principal': '*',
                     'Action': 'kms:Sign', 'Resource': '*',
                     'Condition': {'ArnNotEquals': {'aws:PrincipalArn': role_arn}}}]}}}
        resources[label + 'Alias'] = {'Type': 'AWS::KMS::Alias', 'Properties': {
            'AliasName': 'alias/' + name, 'TargetKeyId': {'Ref': label + 'Key'}}}
        resources[label + 'Role'] = {'Type': 'AWS::IAM::Role', 'Properties': {
            'RoleName': name, 'AssumeRolePolicyDocument': {'Version': '2012-10-17', 'Statement': [
                {'Effect': 'Allow', 'Principal': {'Service': 'lambda.amazonaws.com'},
                 'Action': 'sts:AssumeRole'}]}, 'Policies': [
                {'PolicyName': 'OwnIdentityChallengeOnly', 'PolicyDocument': {
                    'Version': '2012-10-17', 'Statement': [
                        {'Effect': 'Allow', 'Action': ['kms:GetPublicKey'], 'Resource': key_arn},
                        {'Effect': 'Allow', 'Action': ['kms:Sign'], 'Resource': key_arn,
                         'Condition': {'StringEquals': {'kms:SigningAlgorithm': 'ED25519_SHA_512',
                                                       'kms:MessageType': 'RAW'}}},
                        {'Effect': 'Allow', 'Action': ['logs:CreateLogStream', 'logs:PutLogEvents'],
                         'Resource': f'arn:aws:logs:{REGION}:{ACCOUNT}:log-group:/aws/lambda/{name}:*'}]}}]}}
        resources[label + 'Logs'] = {'Type': 'AWS::Logs::LogGroup', 'Properties': {
            'LogGroupName': '/aws/lambda/' + name, 'RetentionInDays': 14}}
        resources[label + 'Function'] = {'Type': 'AWS::Lambda::Function', 'DependsOn': [label + 'Logs'],
            'Properties': {'FunctionName': name, 'Runtime': 'python3.12', 'Architectures': ['x86_64'],
                'Handler': 'factory_runtime.review_role_probe.handler', 'Timeout': 30, 'MemorySize': 128,
                'Role': {'Fn::GetAtt': [label + 'Role', 'Arn']},
                'Code': {'S3Bucket': {'Ref': 'ArtifactBucket'}, 'S3Key': {'Ref': 'ArtifactKey'},
                         'S3ObjectVersion': {'Ref': 'ArtifactVersion'}},
                'Environment': {'Variables': {'FACTORY_REVIEW_ROLE': role,
                    'FACTORY_REVIEW_KEY_ARN': key_arn, 'FACTORY_OPERATIONAL_EXECUTION_ENABLED': 'false'}}}}
        resources[label + 'Version'] = {'Type': 'AWS::Lambda::Version', 'Properties': {
            'FunctionName': {'Ref': label + 'Function'}, 'CodeSha256': {'Ref': 'CodeSha256'}}}
        outputs[label + 'KeyArn'] = {'Value': key_arn}
        outputs[label + 'VersionArn'] = {'Value': {'Ref': label + 'Version'}}
    return {'AWSTemplateFormatVersion': '2010-09-09',
        'Description': 'DRAFT: disabled QA/security identities. Two recurring KMS keys require owner approval. No models, state, secrets, schedules or controller invocation grants.',
        'Parameters': {'ArtifactBucket': {'Type': 'String', 'AllowedValues': [
            'tims-software-factory-666730517561-ca-central-1']},
            **{key: {'Type': 'String'} for key in ('ArtifactKey', 'ArtifactVersion', 'CodeSha256')}},
        'Resources': resources, 'Outputs': outputs}


if __name__ == '__main__':
    path = Path(sys.argv[1])
    with path.open('x', encoding='utf-8', newline='\n') as output:
        output.write(json.dumps(render(), indent=2) + '\n')
    print('PREPARED_ONLY: no cloud changes, model calls or approval granted')
