"""Offline exact-plan QA preview. No signing, deployment or provider calls."""
import base64
import copy
import re

import sign_pilot002_reviewer_allowance as signing
from prepare_pilot002_inspector_live import baseline, STACK, BUCKET
from factory_state.model import StateError


def render(current, plan, package, code, *, approved_digest, now, root=signing.ROOT):
    signing.validate_plan(plan, root=root, role='qa', approved_digest=approved_digest, now=now)
    if current != baseline():
        raise StateError('QA requires the exact disabled pilot baseline')
    sha = package.get('sha256', '')
    if (not isinstance(sha, str) or not re.fullmatch('[0-9a-f]{64}', sha) or
            package.get('source_commit') != signing.QA_SOURCE or
            package.get('activation_sha256') != plan['activation_sha256'] or
            package.get('request_digest') != signing.REQUESTS['qa'] or
            package.get('role') != 'qa' or package.get('execution_enabled') is not False or
            package.get('activation_authorized') is not False or
            package.get('signed_allowance_included') is not False or
            type(package.get('model_calls')) is not int or package['model_calls'] != 0 or
            type(package.get('zip_bytes')) is not int or not 0 < package['zip_bytes'] <= 5000000 or
            package.get('code_sha256') != base64.b64encode(bytes.fromhex(sha)).decode()):
        raise StateError('Exact QA activation package required')
    if (set(code) != {'S3Bucket', 'S3Key', 'S3ObjectVersion'} or code['S3Bucket'] != BUCKET or
            code['S3Key'] != 'pilot-002/runtime/' + signing.QA_SOURCE + '/' + sha + '.zip' or
            not isinstance(code['S3ObjectVersion'], str) or
            not 0 < len(code['S3ObjectVersion']) <= 1024 or code['S3ObjectVersion'] == 'null'):
        raise StateError('Immutable QA package required')
    target = copy.deepcopy(current)
    function = target['Resources']['QaFunction']['Properties']
    function.update(Code=copy.deepcopy(code), Handler='factory_runtime.pilot002_entrypoint.handler',
        Timeout=180, Description='Pilot 002 exact QA request; one permanent attempt, no retry')
    function['Environment']['Variables']['FACTORY_PILOT002_EXECUTION_ENABLED'] = 'true'
    function['Environment']['Variables']['FACTORY_PILOT002_ACTIVATION_SHA256'] = plan['activation_sha256']
    function['Tags'] = [{'Key': 'SourceCommit', 'Value': signing.QA_SOURCE},
        {'Key': 'Purpose', 'Value': 'exact-qa-request'}]
    del function['ReservedConcurrentExecutions']
    return target


def validate(template, changes, plan, package, code, *, approved_digest, now, root=signing.ROOT):
    expected = render(baseline(), plan, package, code, approved_digest=approved_digest, now=now, root=root)
    if (template != expected or changes.get('Status') != 'CREATE_COMPLETE' or
            changes.get('ExecutionStatus') != 'AVAILABLE' or changes.get('StackId') != STACK or
            changes.get('NextToken') or changes.get('Parameters')):
        raise StateError('QA preview is changed or incomplete')
    rows = changes.get('Changes', [])
    if len(rows) != 1:
        raise StateError('Only QA may change')
    row = rows[0]
    resource = row.get('ResourceChange', {})
    if (row.get('Type') != 'Resource' or resource.get('LogicalResourceId') != 'QaFunction' or
            resource.get('ResourceType') != 'AWS::Lambda::Function' or
            resource.get('Action') != 'Modify' or resource.get('Replacement') != 'False'):
        raise StateError('Unexpected QA resource operation')
    return {'status': 'QA_PREVIEW_NOT_EXECUTED', 'maximum_provider_calls': 1, 'retries': 0,
        'reserved_micro_usd': 250000, 'maximum_cost_micro_usd': 0, 'iam_changes': 0,
        'model_calls': 0, 'requires_verified_shutdown': True,
        'requires_fresh_billing_observation': True, 'execution_authorized': False}
