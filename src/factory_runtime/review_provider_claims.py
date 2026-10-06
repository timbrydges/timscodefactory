"""Three fixed permanent holds and one send claim per role; no reset or refund.

Only a deployment-owned backend may supply VerifiedAllowance after re-verifying
its signature and current pricing. This store is not an authorization verifier.
"""
import re
from datetime import datetime
from factory_state.model import SHA256_DIGEST, StateError
from .review_provider_scope import CAP, PROVIDERS, TASK, VerifiedAllowance
from .worker import digest

TABLE = 'tims-factory-bounded-review-001-attempts'


class ReviewProviderClaims:
    def __init__(self, client):
        if (client.meta.endpoint_url != 'https://dynamodb.ca-central-1.amazonaws.com' or
                client.meta.config.retries.get('total_max_attempts') != 1):
            raise StateError('permanent provider claims require regional no-retry DynamoDB')
        self.client = client

    def _item(self, grant, dispatch_id, now):
        if (type(grant) is not VerifiedAllowance or grant.role not in PROVIDERS or
                any(type(v) is not str or not SHA256_DIGEST.fullmatch(v)
                    for v in (grant.allowance_digest, grant.scope_digest)) or
                type(grant.maximum_cost_micro_usd) is not int or not 0 < grant.maximum_cost_micro_usd <= CAP or
                type(dispatch_id) is not str or not re.fullmatch('[0-9a-f]{64}', dispatch_id) or
                type(now) is not datetime or now.tzinfo is None or now.utcoffset() is None or
                type(grant.expires_at) is not int or not now.timestamp() < grant.expires_at <= now.timestamp()+3600):
            raise StateError('fresh verified claim binding required')
        return {'PK': {'S': 'BOUNDED_REVIEW#001#ROLE#'+grant.role}, 'status': {'S': 'RESERVED'},
            'task_id': {'S': TASK}, 'role': {'S': grant.role}, 'dispatch_id': {'S': dispatch_id},
            'allowance_digest': {'S': grant.allowance_digest}, 'scope_digest': {'S': grant.scope_digest},
            'maximum_cost_micro_usd': {'N': str(grant.maximum_cost_micro_usd)},
            'expires_at': {'N': str(grant.expires_at)}, 'reservation_status': {'S': 'HELD'},
            'reserved_micro_usd': {'N': str(CAP)}}

    def hold(self, grant, dispatch_id, *, now):
        item = self._item(grant, dispatch_id, now)
        try:
            self.client.put_item(TableName=TABLE, Item=item, ConditionExpression='attribute_not_exists(PK)')
        except Exception as error:
            if getattr(error, 'response', {}).get('Error', {}).get('Code') != 'ConditionalCheckFailedException':
                raise StateError('reservation outcome uncertain; do not repeat provider work') from None
            existing = self.client.get_item(TableName=TABLE, Key={'PK': item['PK']},
                                            ConsistentRead=True).get('Item')
            if existing != item:
                raise StateError('permanent role hold differs or is already consumed') from None
        return 'RESERVED'

    def _update(self, grant, dispatch_id, now, *, previous, following, output=None, cost=None):
        item = self._item(grant, dispatch_id, now)
        # Bind every immutable hold field, including its qualified maximum.
        fields = [k for k in item if k not in ('PK', 'status')]
        names = {'#s': 'status'}; values = {':before': {'S': previous}, ':after': {'S': following}}
        conditions = ['#s=:before']
        for index, name in enumerate(fields):
            alias, value = '#f'+str(index), ':v'+str(index)
            names[alias] = name; values[value] = item[name]; conditions.append(alias+'='+value)
        update = 'SET #s=:after'
        if output is not None:
            names.update({'#output': 'output_digest', '#cost': 'actual_micro_usd'})
            values.update({':output': {'S': digest(output)}, ':cost': {'N': str(cost)}})
            update += ', #output=:output, #cost=:cost'
        try:
            self.client.update_item(TableName=TABLE, Key={'PK': item['PK']},
                ConditionExpression=' AND '.join(conditions), UpdateExpression=update,
                ExpressionAttributeNames=names, ExpressionAttributeValues=values)
        except Exception:
            raise StateError('provider claim consumed, changed or uncertain; reconcile without retry') from None

    def begin_send(self, grant, dispatch_id, *, now):
        self._update(grant, dispatch_id, now, previous='RESERVED', following='STARTED')

    def complete(self, grant, dispatch_id, *, now, output, actual_micro_usd):
        if (type(output) is not bytes or not 0 < len(output) <= 65536 or
                type(grant) is not VerifiedAllowance or type(actual_micro_usd) is not int or
                not 0 <= actual_micro_usd <= grant.maximum_cost_micro_usd):
            raise StateError('provider result or cost invalid; retain hold')
        self._update(grant, dispatch_id, now, previous='STARTED', following='COMPLETE',
                     output=output, cost=actual_micro_usd)
