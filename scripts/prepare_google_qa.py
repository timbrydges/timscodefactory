"""Prepare Google QA request and credential storage without cloud mutations."""
import argparse
import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))
from factory_runtime.google_qa import ENDPOINT, MODEL, SECRET_NAME, request_body
from factory_runtime.review_preparation import prepare


def credential_template():
    return {'AWSTemplateFormatVersion': '2010-09-09',
        'Description': 'Pending owner approval: empty Google QA secret only; no values or reader grants.',
        'Resources': {'GoogleQaSecret': {'Type': 'AWS::SecretsManager::Secret',
            'DeletionPolicy': 'Retain', 'UpdateReplacePolicy': 'Retain',
            'Properties': {'Name': SECRET_NAME, 'KmsKeyId': 'alias/aws/secretsmanager',
                'Description': 'Dedicated Google QA credential; runtime access not yet granted.'}}}}


def build(root):
    packet = prepare(root, role='qa')
    body = request_body(packet, root=root)
    return {'status': 'PREPARED_NOT_AUTHORIZED', 'provider_family': 'google', 'model_id': MODEL,
        'endpoint': ENDPOINT, 'packet_digest': packet['packet_digest'],
        'request_sha256': hashlib.sha256(body).hexdigest(), 'request_bytes': len(body),
        'request_body': json.loads(body), 'credential_template': credential_template(),
        'credential_setup_proposal': {
            'google_project': 'gen-lang-client-0247455615',
            'google_project_display_name': 'Default Gemini Project',
            'key_display_name': 'Tims Software Factory QA',
            'aws_account': '666730517561', 'aws_region': 'ca-central-1',
            'secret_name': SECRET_NAME, 'runtime_reader_grants': [],
            'new_google_billing_link': False, 'requires_owner_approval': True},
        'model_calls_authorized': 0, 'state_writes_authorized': 0,
        'production_release_authorized': False,
        'remaining_live_gates': ['Dedicated credential creation and storage approval',
            'Google API restriction and project tier verification',
            'Separate scope, live model availability, fresh pricing and budget approval',
            'Exact-input token preflight and output/thinking cap qualification',
            'Durable reservation and attempt claim before generation',
            'Broker-only credential access and Google egress approval',
            'Signed QA report publication and controller verification']}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    plan = build(ROOT)
    with args.output.open('x', encoding='utf-8', newline='\n') as stream:
        stream.write(json.dumps(plan, indent=2, sort_keys=True)+'\n')
    print(json.dumps({k: plan[k] for k in ('status', 'provider_family', 'model_id',
                                         'request_sha256', 'request_bytes', 'model_calls_authorized')}))
