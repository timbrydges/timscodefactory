"""Read-only Sonnet 5.5 account-access diagnostic.

Checks Bedrock availability metadata, AWS Marketplace agreements, and License
Manager received licenses in us-east-1. It performs no subscription, agreement,
grant activation, or model invocation.
"""
from __future__ import annotations

import json

import boto3
from botocore.config import Config

ACCOUNT = '666730517561'
MODEL = 'anthropic.claude-sonnet-5-5'
PROFILE = 'global.anthropic.claude-sonnet-5-5'
PRODUCT_ID = 'prod-pjfguoisodbd6'


def _safe(call):
    try:
        return {'ok': True, 'value': call()}
    except Exception as error:
        response = getattr(error, 'response', {})
        code = response.get('Error', {}).get('Code', type(error).__name__)
        message = response.get('Error', {}).get('Message', str(error))
        return {'ok': False, 'error_code': code, 'error_message': message[:1000]}


def main():
    cfg = Config(connect_timeout=3, read_timeout=10,
                 retries={'total_max_attempts': 1, 'mode': 'standard'})
    session = boto3.Session()
    sts = session.client('sts', region_name='us-east-1', config=cfg)
    identity = sts.get_caller_identity()
    if identity.get('Account') != ACCOUNT:
        raise RuntimeError('wrong AWS account')

    bedrock = session.client('bedrock', region_name='ca-central-1', config=cfg)
    availability = _safe(lambda: bedrock.get_foundation_model_availability(
        modelId=MODEL))
    agreements = _safe(lambda: bedrock.list_foundation_model_agreement_offers(
        modelId=MODEL, offerType='PUBLIC'))

    marketplace = session.client('marketplace-agreement', region_name='us-east-1', config=cfg)
    market = _safe(lambda: marketplace.search_agreements(
        catalog='AWSMarketplace',
        filters=[
            {'name': 'PartyType', 'values': ['Acceptor']},
            {'name': 'AgreementType', 'values': ['PurchaseAgreement']},
            {'name': 'ResourceIdentifier', 'values': [PRODUCT_ID]},
        ],
        maxResults=50))

    iam = session.client('iam', region_name='us-east-1', config=cfg)
    def role_exists(name):
        result = _safe(lambda: iam.get_role(RoleName=name))
        if result['ok']:
            return {'ok': True, 'exists': True}
        if result.get('error_code') == 'NoSuchEntity':
            return {'ok': True, 'exists': False}
        return result

    roles = {
        'AWSServiceRoleForAWSLicenseManagerRole':
            role_exists('AWSServiceRoleForAWSLicenseManagerRole'),
        'AWSServiceRoleForMarketplaceLicenseManagement':
            role_exists('AWSServiceRoleForMarketplaceLicenseManagement'),
    }

    license_manager = session.client('license-manager', region_name='us-east-1', config=cfg)
    if roles['AWSServiceRoleForAWSLicenseManagerRole'].get('exists') is True:
        licenses = _safe(lambda: license_manager.list_received_licenses(MaxResults=100))
        grants = _safe(lambda: license_manager.list_received_grants(MaxResults=100))
    else:
        licenses = {'ok': False, 'skipped': True,
                    'reason': 'AWSServiceRoleForAWSLicenseManagerRole is absent'}
        grants = {'ok': False, 'skipped': True,
                  'reason': 'AWSServiceRoleForAWSLicenseManagerRole is absent'}

    result = {
        'status': 'SONNET_5_5_ACCOUNT_ACCESS_DIAGNOSTIC_READ_ONLY',
        'account': ACCOUNT,
        'model_id': MODEL,
        'inference_profile_id': PROFILE,
        'marketplace_product_id': PRODUCT_ID,
        'bedrock_availability': availability,
        'bedrock_public_offer': agreements,
        'marketplace_agreements': market,
        'service_linked_roles': roles,
        'received_licenses': licenses,
        'received_grants': grants,
        'model_calls': 0,
        'subscriptions_changed': False,
        'licenses_changed': False,
    }
    print(json.dumps(result, sort_keys=True, indent=2, default=str))


if __name__ == '__main__':
    main()
