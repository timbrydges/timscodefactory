"""Read-only reconciliation for the one-shot Inspector review.

Never invokes Lambda or Bedrock and never writes DynamoDB/S3. It checks the
local Lambda error body, the durable one-call budget reservation, exact reviewer
receipt version presence, and recent Inspector Lambda error messages.
"""
from __future__ import annotations

import json
import sys
import time
from pathlib import Path

ACCOUNT = '666730517561'
REGION = 'ca-central-1'
BUDGET_TABLE = 'tims-factory-acceptance-budget'
BUCKET = 'tims-software-factory-666730517561-ca-central-1'
def classify(*, budget_item, reviewer_versions, local_error):
    reserved = bool(budget_item)
    receipt = bool(reviewer_versions)
    if not reserved:
        return {
            'status': 'NO_DURABLE_RESERVATION_FOUND',
            'provider_call_may_have_occurred': False,
            'retry_permitted': False,
            'reason': 'The runtime invokes Bedrock only after a successful durable reservation; investigate the pre-reservation Lambda error before creating any new authorization.',
        }
    if receipt:
        return {
            'status': 'REVIEWER_RECEIPT_FOUND_AFTER_UNCERTAIN_CLIENT_RESULT',
            'provider_call_may_have_occurred': True,
            'retry_permitted': False,
            'reason': 'The one-call reservation exists and an immutable reviewer receipt version exists; do not invoke again.',
        }
    return {
        'status': 'ONE_CALL_RESERVATION_CONSUMED_OR_OUTCOME_UNCERTAIN',
        'provider_call_may_have_occurred': True,
        'retry_permitted': False,
        'reason': 'The one-call reservation exists without a reviewer receipt. This may be a rejected review or a failed/uncertain provider/publication outcome; no retry is permitted.',
        'local_error_present': bool(local_error),
    }


def main():
    if len(sys.argv) != 3:
        raise SystemExit('usage: reconcile_live_inspector_review.py EVENT.json RESULT.json')
    event = json.loads(Path(sys.argv[1]).read_text(encoding='utf-8'))
    plan_digest = event.get('plan', {}).get('plan_digest')
    if not isinstance(plan_digest, str) or not plan_digest.startswith('sha256:'):
        raise RuntimeError('event lacks exact plan digest')
    try:
        activation_id = json.loads(event['request']['user'])['activation_id']
    except (KeyError, TypeError, ValueError) as error:
        raise RuntimeError('event lacks exact Inspector activation id') from error
    if not isinstance(activation_id, str) or not activation_id.startswith('inspector-review-'):
        raise RuntimeError('event Inspector activation id is invalid')

    local_error = None
    result_path = Path(sys.argv[2])
    if result_path.exists():
        raw = result_path.read_text(encoding='utf-8', errors='replace')[:65536]
        try:
            local_error = json.loads(raw)
        except ValueError:
            local_error = {'raw': raw}

    import boto3
    from botocore.config import Config
    config = Config(connect_timeout=3, read_timeout=10,
                    retries={'total_max_attempts':1, 'mode':'standard'})
    session = boto3.Session(region_name=REGION)
    if session.client('sts', config=config).get_caller_identity()['Account'] != ACCOUNT:
        raise RuntimeError('wrong AWS account')

    ddb = session.client('dynamodb', config=config)
    budget = ddb.get_item(
        TableName=BUDGET_TABLE,
        Key={'PK': {'S': 'INSPECTOR#' + activation_id}, 'SK': {'S': 'BUDGET'}},
        ConsistentRead=True).get('Item')

    key = f'factory-scope-receipts/{plan_digest[7:]}/reviewer.json'
    s3 = session.client('s3', config=config)
    listed = s3.list_object_versions(Bucket=BUCKET, Prefix=key, MaxKeys=5)
    versions = [
        {'version_id': item.get('VersionId'), 'is_latest': item.get('IsLatest'),
         'last_modified': item.get('LastModified').isoformat()
            if item.get('LastModified') else None}
        for item in listed.get('Versions', [])
        if item.get('Key') == key
    ]

    logs = session.client('logs', config=config)
    start_ms = int((time.time() - 1800) * 1000)
    events = logs.filter_log_events(
        logGroupName='/aws/lambda/tims-factory-inspector',
        startTime=start_ms, limit=100).get('events', [])
    error_lines = []
    for item in events:
        message = item.get('message', '')
        if any(token in message for token in ('ERROR', 'Error', 'Exception', 'Traceback', 'AccessDenied')):
            error_lines.append(message.strip()[:2000])
    error_lines = error_lines[-12:]

    result = classify(
        budget_item=budget, reviewer_versions=versions, local_error=local_error)
    result.update({
        'activation_id': activation_id,
        'plan_digest': plan_digest,
        'budget_reservation_found': bool(budget),
        'reserved_cost_microusd': (
            budget.get('reserved_cost_microusd', {}).get('N') if budget else None),
        'reviewer_receipt_versions': versions,
        'local_lambda_error': local_error,
        'recent_inspector_error_lines': error_lines,
        'aws_operations': 'READ_ONLY',
        'model_invocations_by_reconciler': 0,
    })
    print(json.dumps(result, sort_keys=True, indent=2, default=str))


if __name__ == '__main__':
    main()
