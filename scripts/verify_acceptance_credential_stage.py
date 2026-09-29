"""Verify the staged acceptance credential without retrieving its value.

This is a disabled deployment check, not a provider authentication test or
permission to activate the broker.
"""
from __future__ import annotations

import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

try:
    from .prepare_acceptance_broker_iam import (
        ACCOUNT, ENVIRONMENT, FUNCTION, POLICY_ARNS,
        POLICY_NAMES, REGION, ROLE, _assert_policy_documents, aws, source,
    )
except ImportError:
    from prepare_acceptance_broker_iam import (
        ACCOUNT, ENVIRONMENT, FUNCTION, POLICY_ARNS,
        POLICY_NAMES, REGION, ROLE, _assert_policy_documents, aws, source,
    )

SECRET = 'tims-software-factory/provider/openai/acceptance'
ALIAS = 'alias/tims-software-factory-provider-credentials'
STACK = 'tims-factory-acceptance-broker'
BROKER_VERSION = 4
COMPOSITION_COMMIT = '39c7a3b19a2f50d3d9bef19b04e69024d51032e4'


def verify() -> dict:
    if aws('sts', 'get-caller-identity').get('Account') != ACCOUNT:
        raise RuntimeError('acceptance credential is in the wrong AWS account')
    commit = source()
    secret = aws('secretsmanager', 'describe-secret', '--secret-id', SECRET)
    arn = secret.get('ARN')
    prefix = f'arn:aws:secretsmanager:{REGION}:{ACCOUNT}:secret:{SECRET}-'
    if (secret.get('Name') != SECRET or not isinstance(arn, str) or
            not arn.startswith(prefix) or not re.fullmatch(r'[A-Za-z0-9]{6}', arn[len(prefix):]) or
            secret.get('DeletedDate') is not None):
        raise RuntimeError('acceptance provider secret identity differs')
    versions = secret.get('VersionIdsToStages')
    if (not isinstance(versions, dict) or not versions or
            sum('AWSCURRENT' in stages for stages in versions.values()
                if isinstance(stages, list)) != 1 or
            any(not isinstance(stages, list) for stages in versions.values())):
        raise RuntimeError('exactly one AWSCURRENT provider secret version is required')

    key_arn = secret.get('KmsKeyId')
    if (not isinstance(key_arn, str) or
            not key_arn.startswith(f'arn:aws:kms:{REGION}:{ACCOUNT}:key/')):
        raise RuntimeError('provider secret KMS binding differs')
    key = aws('kms', 'describe-key', '--key-id', ALIAS)['KeyMetadata']
    if (key.get('Arn') != key_arn or key.get('KeyState') != 'Enabled' or
            key.get('KeyManager') != 'CUSTOMER' or
            aws('kms', 'get-key-rotation-status', '--key-id', key_arn).get(
                'KeyRotationEnabled') is not True):
        raise RuntimeError('provider credential key is not enabled and rotating')

    attached = aws('iam', 'list-attached-role-policies', '--role-name', ROLE)
    bindings = {(item.get('PolicyName'), item.get('PolicyArn')) for item in
                attached.get('AttachedPolicies', [])}
    if (bindings != set(zip(POLICY_NAMES, POLICY_ARNS)) or
            len(attached.get('AttachedPolicies', [])) != 2 or
            attached.get('IsTruncated') is True):
        raise RuntimeError('broker role does not have the exact two policies')
    _assert_policy_documents()

    stack = aws('cloudformation', 'describe-stacks', '--stack-name', STACK)['Stacks'][0]
    if stack.get('StackStatus') not in {'CREATE_COMPLETE', 'UPDATE_COMPLETE'}:
        raise RuntimeError('broker stack is not complete')
    outputs = {item['OutputKey']: item['OutputValue'] for item in stack['Outputs']}
    broker = outputs.get('BrokerVersionArn')
    expected = f'arn:aws:lambda:{REGION}:{ACCOUNT}:function:{FUNCTION}:{BROKER_VERSION}'
    if broker != expected:
        raise RuntimeError('expected pinned disabled broker version 4')
    latest_arn = expected.rsplit(':', 1)[0]
    for function_arn in (broker, latest_arn):
        config = aws('lambda', 'get-function-configuration', '--function-name', function_arn)
        if (config.get('FunctionArn') != function_arn or
                config.get('Environment', {}).get('Variables') != ENVIRONMENT or
                config.get('Role') != f'arn:aws:iam::{ACCOUNT}:role/{ROLE}' or
                config.get('State') != 'Active'):
            raise RuntimeError('broker code path is not disabled')

    return {'status': 'DISABLED_BROKER_CREDENTIAL_STAGE_VERIFIED',
            'source_commit': commit, 'broker_source_commit': COMPOSITION_COMMIT,
            'observed_at': datetime.now(timezone.utc).isoformat(),
            'region': REGION, 'function_arn': broker,
            'provider_secret_arn': arn, 'current_secret_versions': 1,
            'kms_rotation_enabled': True,
            'attached_policies': list(POLICY_ARNS),
            'broker_enabled': False, 'secret_values_read': False,
            'provider_calls_by_verifier': 0}


if __name__ == '__main__':
    if len(sys.argv) != 2:
        raise SystemExit('usage: verify_acceptance_credential_stage.py OUTPUT_JSON')
    result = verify()
    Path(sys.argv[1]).write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(result, indent=2))
