"""Match runtime, owner evidence and exact budget IAM before deployment/calls."""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))
from factory_runtime.lambda_role import INSPECTOR_ACTIVATION_ID, INSPECTOR_AUTHORIZATION_ID


def expected_reservation():
    return {'Sid': 'ReserveExactInspectorReview', 'Effect': 'Allow',
        'Action': ['dynamodb:PutItem'],
        'Resource': 'arn:aws:dynamodb:ca-central-1:666730517561:table/tims-factory-acceptance-budget',
        'Condition': {'ForAllValues:StringEquals': {
            'dynamodb:LeadingKeys': ['INSPECTOR#' + INSPECTOR_ACTIVATION_ID]}}}


def verify_policy(policy):
    statements = [s for s in policy.get('Statement', []) if s.get('Sid') == 'ReserveExactInspectorReview']
    if statements != [expected_reservation()]:
        raise RuntimeError('Inspector budget IAM differs from the runtime activation; no invocation allowed')


def verify(root=ROOT):
    record = json.loads((root / f'factory/evidence/{INSPECTOR_AUTHORIZATION_ID}.json').read_text())
    if record.get('event_id') != INSPECTOR_AUTHORIZATION_ID or record.get('activation_id') != INSPECTOR_ACTIVATION_ID:
        raise RuntimeError('Inspector authorization evidence differs from runtime activation')
    template = json.loads((root / 'infra/roles/functions.cloudformation.json').read_text())
    policy = template['Resources']['InspectorRole']['Properties']['Policies'][1]['Fn::If'][1]['PolicyDocument']
    verify_policy(policy)
    return {'activation_id': INSPECTOR_ACTIVATION_ID, 'authorization_id': INSPECTOR_AUTHORIZATION_ID,
            'status': 'INSPECTOR_ACTIVATION_BINDING_VERIFIED', 'model_calls': 0}


if __name__ == '__main__':
    print(json.dumps(verify()))
