"""Render an exact, unattached Bedrock policy for acceptance Inspector review.

Input is a fresh GetInferenceProfile response captured in ca-central-1. This
preparation has no AWS client, model call, role attachment, or spending effect.
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ACCOUNT = '666730517561'
REGION = 'ca-central-1'
PROFILE = re.compile(r'arn:aws:bedrock:ca-central-1:666730517561:'
                     r'inference-profile/(global\.anthropic\.[a-z0-9.:-]+)\Z')
MODEL = re.compile(r'arn:aws:bedrock:([a-z0-9-]+)::'
                   r'foundation-model/(anthropic\.[a-z0-9.:-]+)\Z')


def build_policy(description: dict) -> dict:
    if not isinstance(description, dict):
        raise ValueError('Inspector inference profile is missing')
    arn = description.get('inferenceProfileArn')
    match = PROFILE.fullmatch(arn) if isinstance(arn, str) else None
    if (match is None or description.get('status') != 'ACTIVE' or
            description.get('type') != 'SYSTEM_DEFINED' or
            description.get('inferenceProfileId') != match[1] or
            not isinstance(description.get('models'), list) or
            not description['models']):
        raise ValueError('Inspector inference profile is not the active global Anthropic profile')
    model_id = match[1].removeprefix('global.')
    regions = set()
    for item in description['models']:
        model_arn = item.get('modelArn') if isinstance(item, dict) else None
        found = MODEL.fullmatch(model_arn) if isinstance(model_arn, str) else None
        if found is None or found[2] != model_id:
            raise ValueError('Inspector profile routes to an unexpected model')
        regions.add(found[1])
    # Global inference also evaluates the source Region and a regionless
    # foundation-model ARN. Neither is a wildcard permission.
    resources = [f'arn:aws:bedrock:{region}::foundation-model/{model_id}'
                 for region in sorted(regions | {REGION})]
    resources.append(f'arn:aws:bedrock:::foundation-model/{model_id}')
    return {'Version': '2012-10-17', 'Statement': [
        {'Sid': 'ExactInspectorProfile', 'Effect': 'Allow',
         'Action': 'bedrock:InvokeModel', 'Resource': arn,
         'Condition': {'StringEquals': {'aws:RequestedRegion': REGION}}},
        {'Sid': 'ModelOnlyViaInspectorProfile', 'Effect': 'Allow',
         'Action': 'bedrock:InvokeModel', 'Resource': resources,
         'Condition': {'StringEquals': {'bedrock:InferenceProfileArn': arn}}}]}


def main():
    if len(sys.argv) != 3:
        raise SystemExit('usage: prepare_acceptance_inspector_iam.py '
                         'GET_INFERENCE_PROFILE.json POLICY.json')
    policy = build_policy(json.loads(Path(sys.argv[1]).read_text()))
    Path(sys.argv[2]).write_text(json.dumps(policy, sort_keys=True, indent=2) + '\n')
    print(json.dumps({'status': 'PREPARED_UNATTACHED',
                      'profile': policy['Statement'][0]['Resource'],
                      'model_calls_authorized': 0}))


if __name__ == '__main__':
    main()
