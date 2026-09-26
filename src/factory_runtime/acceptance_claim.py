"""Durable broker-side at-most-once claim for one acceptance dispatch."""
from __future__ import annotations

import json
from dataclasses import dataclass

from factory_state.model import SAFE_IDENTIFIER, SHA256_DIGEST, StateError
from factory_state.scope import canonical


@dataclass
class DynamoDBAcceptanceClaimStore:
    table_name: str
    client: object

    def __post_init__(self):
        if self.table_name != 'tims-factory-acceptance-broker-claims':
            raise StateError('acceptance broker claims require the isolated table')

    @staticmethod
    def _key(activation_id, dispatch_id):
        if (not isinstance(activation_id, str) or not SAFE_IDENTIFIER.fullmatch(activation_id) or
                not isinstance(dispatch_id, str) or not SAFE_IDENTIFIER.fullmatch(dispatch_id)):
            raise StateError('invalid acceptance broker claim identity')
        return {'PK': {'S': f'ACTIVATION#{activation_id}'}, 'SK': {'S': f'CALL#{dispatch_id}'}}

    @staticmethod
    def _digest(event_digest):
        if not isinstance(event_digest, str) or not SHA256_DIGEST.fullmatch(event_digest):
            raise StateError('invalid acceptance broker event digest')

    def begin(self, *, activation_id, dispatch_id, event_digest):
        key = self._key(activation_id, dispatch_id)
        self._digest(event_digest)
        item = {**key, 'event_digest': {'S': event_digest}, 'status': {'S': 'STARTED'}}
        try:
            self.client.put_item(TableName=self.table_name, Item=item,
                                 ConditionExpression='attribute_not_exists(PK) AND attribute_not_exists(SK)')
            return None
        except Exception as error:
            try:
                prior = self.client.get_item(TableName=self.table_name, Key=key,
                                             ConsistentRead=True).get('Item')
            except Exception:
                raise StateError('acceptance broker claim outcome unknown') from error
            if (not isinstance(prior, dict) or prior.get('event_digest') != {'S': event_digest}):
                raise StateError('acceptance broker claim conflicted or outcome unknown') from error
            if prior.get('status') == {'S': 'COMPLETE'} and 'response' in prior:
                try:
                    return json.loads(prior['response']['S'])
                except (KeyError, ValueError, TypeError) as invalid:
                    raise StateError('acceptance broker completed claim is invalid') from invalid
            raise StateError('acceptance broker call already started; reconciliation required') from error

    def complete(self, *, activation_id, dispatch_id, event_digest, response):
        key = self._key(activation_id, dispatch_id)
        self._digest(event_digest)
        self.client.update_item(TableName=self.table_name, Key=key,
            UpdateExpression='SET #s=:done, #r=:response',
            ConditionExpression='#s=:started AND event_digest=:digest',
            ExpressionAttributeNames={'#s': 'status', '#r': 'response'},
            ExpressionAttributeValues={':done': {'S': 'COMPLETE'}, ':started': {'S': 'STARTED'},
                ':digest': {'S': event_digest}, ':response': {'S': canonical(response).decode()}})
