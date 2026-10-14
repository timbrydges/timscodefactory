"""Proposed read-only probe. Not deployed; no provider, signing or write calls."""
TABLE = 'tims-software-factory-state'
TASK = 'FACTORY#tims-software-factory#TASK#bounded-review-004'

def probe(event, client):
    if event != {'operation': 'verify-security-source-access'}:
        raise ValueError('Exact diagnostic operation required')
    results = {}
    for label, key in [('exact_task', TASK), ('outside_scope', TASK + '-access-probe-denied')]:
        try:
            response = client.get_item(TableName=TABLE,
                Key={'PK': {'S': key}, 'SK': {'S': 'STATE'}}, ConsistentRead=True,
                ProjectionExpression='#s,#v', ExpressionAttributeNames={'#s':'state','#v':'version'})
            results[label] = {'decision':'allowed','record_present':bool(response.get('Item'))}
        except Exception as error:
            code = getattr(error, 'response', {}).get('Error', {}).get('Code')
            if code != 'AccessDeniedException':
                raise
            results[label] = {'decision':'denied'}
    return results

def handler(event, context):
    import boto3
    from botocore.config import Config
    return probe(event, boto3.client('dynamodb', region_name='ca-central-1',
        config=Config(retries={'total_max_attempts':1},connect_timeout=3,read_timeout=5)))
