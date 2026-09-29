"""No-charge, dummy-text token counting availability probe for Sonnet 5.5.

It makes CountTokens requests only. It never sends acceptance task material,
reserves a budget, invokes a model, or enables an operational switch.
"""
from __future__ import annotations

import json
import urllib.error
import urllib.request

import boto3
from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest

ACCOUNT = '666730517561'
PROFILE = 'global.anthropic.claude-sonnet-5-5'
MODEL = 'anthropic.claude-sonnet-5-5'
PROMPT = 'Count this harmless test sentence.'


def main():
    if boto3.client('sts', region_name='ca-central-1').get_caller_identity()['Account'] != ACCOUNT:
        raise RuntimeError('wrong AWS account')
    body = {'anthropic_version': 'bedrock-2023-05-31', 'max_tokens': 1,
            'messages': [{'role': 'user', 'content': PROMPT}]}
    runtime = boto3.client('bedrock-runtime', region_name='ca-central-1')
    try:
        response = runtime.count_tokens(modelId=PROFILE,
            input={'invokeModel': {'body': json.dumps(body)}})
        print(json.dumps({'path': 'bedrock-runtime/ca-central-1',
                          'status': 'SUPPORTED', 'input_tokens': response['inputTokens']}))
    except Exception as error:
        code = getattr(error, 'response', {}).get('Error', {}).get('Code', type(error).__name__)
        print(json.dumps({'path': 'bedrock-runtime/ca-central-1',
                          'status': 'UNAVAILABLE', 'error_code': code}))

    # AWS documents this path for CRIS-only Claude models. The regional
    # Mantle endpoint is unavailable in Canada, so use US East with dummy text.
    url = 'https://bedrock-mantle.us-east-1.api.aws/anthropic/v1/messages/count_tokens'
    payload = json.dumps({'model': MODEL,
                          'messages': [{'role': 'user', 'content': PROMPT}]},
                         separators=(',', ':')).encode()
    credentials = boto3.Session().get_credentials()
    if credentials is None:
        raise RuntimeError('AWS credentials unavailable')
    signed = AWSRequest(method='POST', url=url, data=payload,
        headers={'Content-Type': 'application/json', 'anthropic-version': '2023-06-01'})
    SigV4Auth(credentials.get_frozen_credentials(), 'bedrock-mantle', 'us-east-1').add_auth(signed)
    request = urllib.request.Request(url, data=payload, headers=dict(signed.headers), method='POST')
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            result = json.load(response)
        count = result.get('input_tokens')
        if type(count) is not int or count <= 0:
            raise RuntimeError('unexpected token count response')
        print(json.dumps({'path': 'bedrock-mantle/us-east-1',
                          'status': 'SUPPORTED', 'input_tokens': count}))
    except urllib.error.HTTPError as error:
        print(json.dumps({'path': 'bedrock-mantle/us-east-1',
                          'status': 'UNAVAILABLE', 'http_status': error.code}))
    print(json.dumps({'model_calls': 0, 'task_material_sent': False}))


if __name__ == '__main__':
    main()
