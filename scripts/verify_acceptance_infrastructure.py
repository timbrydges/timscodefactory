"""Read-only proof of the disabled acceptance infrastructure in ca-central-1.

Never fetch the provider secret value. The secret must still be empty, and the
five prepared IAM policies must remain unattached at this stage.
"""
from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

try:
    from .prepare_role_deployment import ACCOUNT, REGION, aws, source
except ImportError:
    from prepare_role_deployment import ACCOUNT, REGION, aws, source

TABLES = ('tims-factory-acceptance-budget', 'tims-factory-acceptance-broker-claims')
SECRET = 'tims-software-factory/provider/openai/acceptance'
ALIAS = 'alias/tims-software-factory-provider-credentials'
POLICIES = (
    'tims-software-factory-acceptance-budget-builder',
    'tims-software-factory-acceptance-broker-records',
    'tims-software-factory-provider-broker-secret-reader',
    'tims-software-factory-owner-receipt-writer',
    'tims-software-factory-reviewer-receipt-writer',
)


def verify() -> dict:
    if aws('sts', 'get-caller-identity').get('Account') != ACCOUNT:
        raise RuntimeError('acceptance infrastructure is in the wrong AWS account')
    commit = source()
    for name in TABLES:
        table = aws('dynamodb', 'describe-table', '--table-name', name)['Table']
        if (table.get('TableName') != name or table.get('TableStatus') != 'ACTIVE' or
                table.get('DeletionProtectionEnabled') is not True or
                table.get('SSEDescription', {}).get('Status') != 'ENABLED'):
            raise RuntimeError(f'acceptance table is not protected and active: {name}')
        backups = aws('dynamodb', 'describe-continuous-backups', '--table-name', name)
        recovery = backups.get('ContinuousBackupsDescription', {}).get('PointInTimeRecoveryDescription', {})
        if recovery.get('PointInTimeRecoveryStatus') != 'ENABLED':
            raise RuntimeError(f'acceptance table recovery is disabled: {name}')

    secret = aws('secretsmanager', 'describe-secret', '--secret-id', SECRET)
    if (secret.get('Name') != SECRET or secret.get('DeletedDate') is not None or
            secret.get('VersionIdsToStages', {}) != {}):
        raise RuntimeError('acceptance provider secret is deleted, versioned or different')
    key_arn = secret.get('KmsKeyId')
    if not isinstance(key_arn, str) or not key_arn.startswith(f'arn:aws:kms:{REGION}:{ACCOUNT}:key/'):
        raise RuntimeError('acceptance secret does not use the approved KMS key')
    key = aws('kms', 'describe-key', '--key-id', key_arn)['KeyMetadata']
    if (key.get('Arn') != key_arn or key.get('KeyState') != 'Enabled' or
            key.get('KeyManager') != 'CUSTOMER' or
            aws('kms', 'get-key-rotation-status', '--key-id', key_arn).get('KeyRotationEnabled') is not True):
        raise RuntimeError('acceptance credential KMS key is not enabled and rotating')
    aliases = aws('kms', 'list-aliases', '--key-id', key['KeyId'])
    if (aliases.get('Truncated') is True or
            not any(item.get('AliasName') == ALIAS and item.get('TargetKeyId') == key['KeyId']
                    for item in aliases.get('Aliases', []))):
        raise RuntimeError('acceptance credential KMS alias differs')

    for name in POLICIES:
        arn = f'arn:aws:iam::{ACCOUNT}:policy/{name}'
        policy = aws('iam', 'get-policy', '--policy-arn', arn)['Policy']
        if policy.get('Arn') != arn or policy.get('AttachmentCount') != 0:
            raise RuntimeError(f'acceptance policy is missing or attached: {name}')
        entities = aws('iam', 'list-entities-for-policy', '--policy-arn', arn)
        if (entities.get('IsTruncated') is True or
                any(entities.get(field) for field in ('PolicyGroups', 'PolicyRoles', 'PolicyUsers'))):
            raise RuntimeError(f'acceptance policy has an attachment: {name}')
    return {'status': 'DISABLED_ACCEPTANCE_INFRASTRUCTURE_VERIFIED',
            'source_commit': commit, 'region': REGION,
            'observed_at': datetime.now(timezone.utc).isoformat(),
            'tables_active_and_protected': list(TABLES), 'provider_secret_versions': 0,
            'credential_key_rotation_enabled': True,
            'unattached_policies': list(POLICIES),
            'secret_values_read': False, 'provider_calls_by_verifier': 0}


if __name__ == '__main__':
    if len(sys.argv) != 2:
        raise SystemExit('usage: verify_acceptance_infrastructure.py OUTPUT_JSON')
    result = verify()
    Path(sys.argv[1]).write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(result, indent=2))
