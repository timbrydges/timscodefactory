"""Read-only account-access probe for Claude Sonnet 4.6 fallback.

This uses only Bedrock control-plane APIs. It does not accept terms, modify IAM,
reserve budget, invoke a model, or send Factory task material.
"""
from __future__ import annotations

import json

ACCOUNT = '666730517561'
REGION = 'ca-central-1'
MODEL = 'anthropic.claude-sonnet-4-6'
PROFILE = 'global.anthropic.claude-sonnet-4-6'


def probe(client_factory):
    bedrock = client_factory('bedrock', region_name=REGION)
    result = {
        'region': REGION,
        'model': MODEL,
        'profile': PROFILE,
        'model_calls': 0,
        'task_material_sent': False,
        'access_changed': False,
    }
    try:
        availability = bedrock.get_foundation_model_availability(modelId=MODEL)
        result['agreement'] = availability.get('agreementAvailability', {}).get('status')
        result['authorization'] = availability.get('authorizationStatus')
        result['entitlement'] = availability.get('entitlementAvailability')
        result['region_availability'] = availability.get('regionAvailability')
    except Exception as error:
        result['availability_error_code'] = getattr(
            error, 'response', {}).get('Error', {}).get('Code', type(error).__name__)

    try:
        offers = bedrock.list_foundation_model_agreement_offers(
            modelId=MODEL, offerType='PUBLIC')
        result['public_offer_count'] = len(offers.get('offers', []))
    except Exception as error:
        result['offer_error_code'] = getattr(
            error, 'response', {}).get('Error', {}).get('Code', type(error).__name__)

    try:
        profile = bedrock.get_inference_profile(inferenceProfileIdentifier=PROFILE)
        result['profile_status'] = profile.get('status')
        result['profile_type'] = profile.get('type')
        result['profile_models'] = [
            item.get('modelArn') for item in profile.get('models', [])
            if isinstance(item, dict) and isinstance(item.get('modelArn'), str)
        ]
    except Exception as error:
        result['profile_error_code'] = getattr(
            error, 'response', {}).get('Error', {}).get('Code', type(error).__name__)

    try:
        use_case = bedrock.get_use_case_for_model_access()
        result['anthropic_use_case_present'] = bool(use_case.get('formData'))
    except Exception as error:
        result['use_case_error_code'] = getattr(
            error, 'response', {}).get('Error', {}).get('Code', type(error).__name__)

    result['status'] = 'SONNET_4_6_ACCOUNT_ACCESS_PROBE_ONLY'
    return result


def main():
    import boto3
    account = boto3.client('sts', region_name=REGION).get_caller_identity()['Account']
    if account != ACCOUNT:
        raise RuntimeError('wrong AWS account')
    print(json.dumps(probe(boto3.client), sort_keys=True))


if __name__ == '__main__':
    main()
