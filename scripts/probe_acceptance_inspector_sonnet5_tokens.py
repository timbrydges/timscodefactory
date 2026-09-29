"""No-charge dummy-text CountTokens probe for a possible Sonnet 5 fallback.

This neither changes the selected Sonnet 5.5 profile nor authorizes provider
spending. It makes only one count request and never sends task material.
"""
from __future__ import annotations

import json
import urllib.error
import urllib.request

import boto3
from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest

ACCOUNT = '666730517561'
REGION = 'us-east-1'
MODEL = 'anthropic.claude-sonnet-5'
URL = 'https://bedrock-mantle.us-east-1.api.aws/anthropic/v1/messages/count_tokens'


def main():
    if boto3.client('sts', region_name='ca-central-1').get_caller_identity()['Account'] != ACCOUNT:
        raise RuntimeError('wrong AWS account')
    payload = json.dumps({'model': MODEL,
        'messages': [{'role': 'user', 'content': 'Count this harmless test sentence.'}]},
        separators=(',', ':')).encode()
    credentials = boto3.Session().get_credentials()
    if credentials is None:
        raise RuntimeError('AWS credentials unavailable')
    signed = AWSRequest(method='POST', url=URL, data=payload,
        headers={'Content-Type': 'application/json', 'anthropic-version': '2023-06-01'})
    SigV4Auth(credentials.get_frozen_credentials(), 'bedrock-mantle', REGION).add_auth(signed)
    request = urllib.request.Request(URL, data=payload, headers=dict(signed.headers), method='POST')
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            count = json.load(response).get('input_tokens')
        if type(count) is not int or count <= 0:
            raise RuntimeError('unexpected token count response')
        print(json.dumps({'path': 'bedrock-mantle/us-east-1', 'model': MODEL,
                          'status': 'SUPPORTED', 'input_tokens': count}))
    except urllib.error.HTTPError as error:
        print(json.dumps({'path': 'bedrock-mantle/us-east-1', 'model': MODEL,
                          'status': 'UNAVAILABLE', 'http_status': error.code}))
    print(json.dumps({'model_calls': 0, 'task_material_sent': False,
                      'selected_model_unchanged': True}))


if __name__ == '__main__':
    main()
