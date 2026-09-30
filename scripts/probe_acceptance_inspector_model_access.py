"""Read-only Bedrock account availability inventory for Inspector candidates.

This calls only the Bedrock control-plane GetFoundationModelAvailability API.
It does not count tokens, invoke a model, agree to terms, or grant access.
"""
from __future__ import annotations

import json

ACCOUNT = '666730517561'
CANDIDATES = (
    ('ca-central-1', 'anthropic.claude-sonnet-5-5'),
    ('us-east-1', 'anthropic.claude-sonnet-5'),
    ('ca-central-1', 'anthropic.claude-sonnet-4-6'),
    ('ca-central-1', 'anthropic.claude-3-haiku-20240307-v1:0'),
)


def inventory(client_factory):
    result = []
    for region, model in CANDIDATES:
        client = client_factory('bedrock', region_name=region)
        try:
            response = client.get_foundation_model_availability(modelId=model)
            if response.get('modelId') != model:
                raise ValueError('model availability response differs from request')
            agreement = response.get('agreementAvailability', {})
            result.append({'region': region, 'model': model,
                'agreement': agreement.get('status'),
                'authorization': response.get('authorizationStatus'),
                'entitlement': response.get('entitlementAvailability'),
                'region_availability': response.get('regionAvailability')})
        except Exception as error:
            code = getattr(error, 'response', {}).get('Error', {}).get('Code', type(error).__name__)
            result.append({'region': region, 'model': model, 'error_code': code})
    return {'status': 'ACCOUNT_ACCESS_INVENTORY_ONLY', 'candidates': result,
            'model_calls': 0, 'task_material_sent': False, 'access_changed': False}


def main():
    import boto3

    account = boto3.client('sts', region_name='ca-central-1').get_caller_identity()['Account']
    if account != ACCOUNT:
        raise RuntimeError('wrong AWS account')
    print(json.dumps(inventory(boto3.client), sort_keys=True))


if __name__ == '__main__':
    main()
