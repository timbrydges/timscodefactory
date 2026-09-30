"""Read-only Anthropic first-use and model agreement diagnostic.

Returns only use-case presence and offer count. It never prints the
submitted use case, offer tokens, or signed legal URLs, and never creates
an agreement.
"""
from __future__ import annotations

import json

ACCOUNT = '666730517561'
REGION = 'ca-central-1'
MODEL = 'anthropic.claude-sonnet-5-5'


def _error_code(error):
    return getattr(error, 'response', {}).get('Error', {}).get('Code', type(error).__name__)


def diagnose(client):
    result = {'status': 'INSPECTOR_AGREEMENT_DIAGNOSTIC_ONLY',
              'region': REGION, 'model': MODEL,
              'model_calls': 0, 'task_material_sent': False,
              'access_changed': False}
    try:
        use_case = client.get_use_case_for_model_access()
        result['anthropic_use_case_present'] = bool(use_case.get('formData'))
    except Exception as error:
        result['anthropic_use_case_error_code'] = _error_code(error)
    try:
        offers = client.list_foundation_model_agreement_offers(modelId=MODEL,
                                                               offerType='PUBLIC')
        if offers.get('modelId') != MODEL:
            raise ValueError('agreement offers response differs from request')
        result['public_offer_count'] = len(offers.get('offers', []))
    except Exception as error:
        result['public_offers_error_code'] = _error_code(error)
    return result


def main():
    import boto3

    account = boto3.client('sts', region_name=REGION).get_caller_identity()['Account']
    if account != ACCOUNT:
        raise RuntimeError('wrong AWS account')
    print(json.dumps(diagnose(boto3.client('bedrock', region_name=REGION)),
                     sort_keys=True))


if __name__ == '__main__':
    main()
