"""Render a review-only, activation-specific controller IAM policy.

This command has no AWS client and cannot attach the policy or enable a Lambda.
The signed receipt and job pins must come from a separately reviewed deployment.
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path


ACCOUNT = '666730517561'
REGION = 'ca-central-1'
BUCKET = f'tims-software-factory-{ACCOUNT}-{REGION}'
SAFE_ID = re.compile(r'[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z')
VERSION = re.compile(r'[^\s*?]{1,1024}\Z')
DIGEST = re.compile(r'sha256:[0-9a-f]{64}\Z')
BUILDER = re.compile(
    rf'arn:aws:lambda:{REGION}:{ACCOUNT}:function:tims-factory-builder:[1-9][0-9]*\Z')


def _exact(value, pattern, label):
    if not isinstance(value, str) or not pattern.fullmatch(value):
        raise ValueError(f'invalid {label}')
    return value


def build_policy(binding: dict) -> dict:
    """Bind one task, budget, immutable job and receipt pair, and Builder version."""
    if not isinstance(binding, dict) or set(binding) != {
            'activation_id', 'builder_version_arn', 'job_version_id',
            'receipt_plan_digest', 'owner_receipt_version_id',
            'reviewer_receipt_version_id'}:
        raise ValueError('controller IAM binding has missing or extra fields')
    activation = _exact(binding['activation_id'], SAFE_ID, 'activation ID')
    builder = _exact(binding['builder_version_arn'], BUILDER, 'Builder version ARN')
    plan = _exact(binding['receipt_plan_digest'], DIGEST, 'receipt plan digest')[7:]
    versions = [
        _exact(binding['job_version_id'], VERSION, 'job version'),
        _exact(binding['owner_receipt_version_id'], VERSION, 'owner receipt version'),
        _exact(binding['reviewer_receipt_version_id'], VERSION, 'reviewer receipt version'),
    ]
    if any(version == 'null' for version in versions):
        raise ValueError('unversioned S3 objects cannot be authorized')
    object_keys = [f'factory-autonomy-jobs/{activation}/IMPLEMENTATION.json',
                   f'factory-scope-receipts/{plan}/owner.json',
                   f'factory-scope-receipts/{plan}/reviewer.json']
    statements = [
        {'Sid': 'OneTaskAndScope', 'Effect': 'Allow',
         'Action': ['dynamodb:GetItem', 'dynamodb:PutItem', 'dynamodb:UpdateItem',
                    'dynamodb:ConditionCheckItem'],
         'Resource': f'arn:aws:dynamodb:{REGION}:{ACCOUNT}:table/tims-software-factory-state',
         'Condition': {'Null': {'dynamodb:LeadingKeys': 'false'},
                       'ForAllValues:StringLike': {'dynamodb:LeadingKeys': [
             'FACTORY#tims-software-factory#TASK#deterministic-text-fingerprint',
             'FACTORY#tims-software-factory#TASK#SCOPE#OBJECTIVE#*']}}},
        {'Sid': 'OneActivationBudget', 'Effect': 'Allow',
         'Action': ['dynamodb:GetItem', 'dynamodb:PutItem', 'dynamodb:UpdateItem'],
         'Resource': f'arn:aws:dynamodb:{REGION}:{ACCOUNT}:table/tims-factory-acceptance-budget',
         'Condition': {'Null': {'dynamodb:LeadingKeys': 'false'},
                       'ForAllValues:StringEquals': {
             'dynamodb:LeadingKeys': [f'ACTIVATION#{activation}']}}},
    ]
    for name, key, version in zip(('Job', 'OwnerReceipt', 'ReviewerReceipt'), object_keys, versions):
        statements.append({'Sid': f'Pinned{name}', 'Effect': 'Allow',
                           'Action': 's3:GetObjectVersion',
                           'Resource': f'arn:aws:s3:::{BUCKET}/{key}',
                           'Condition': {'StringEquals': {'s3:VersionId': version}}})
    statements.append({'Sid': 'PinnedBuilder', 'Effect': 'Allow',
                       'Action': 'lambda:InvokeFunction', 'Resource': builder})
    return {'Version': '2012-10-17', 'Statement': statements}


def main():
    if len(sys.argv) != 3:
        raise SystemExit('usage: prepare_acceptance_controller_iam.py BINDING.json POLICY.json')
    # No invocation, attachment, or AWS credentials are needed to prepare this artifact.
    binding = json.loads(Path(sys.argv[1]).read_text())
    policy = build_policy(binding)
    Path(sys.argv[2]).write_text(json.dumps(policy, indent=2, sort_keys=True) + '\n')


if __name__ == '__main__':
    main()
