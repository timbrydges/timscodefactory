"""Durable, fail-closed reservation of the exact owner-approved acceptance calls.

Reservations count attempted calls. A lost transaction response is reconciled by
reading its immutable dispatch record; it never authorizes another reservation.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from decimal import Decimal
from typing import Any

from factory_state.model import SAFE_IDENTIFIER, StateError


@dataclass
class DynamoDBAcceptanceBudgetStore:
    table_name: str
    client: Any

    def __post_init__(self) -> None:
        if self.table_name != 'tims-factory-acceptance-budget':
            raise StateError('acceptance budget requires its isolated table')

    def reserve(self, *, activation_id: str, dispatch_id: str,
                maximum_cost_usd: Decimal, maximum_provider_calls: int,
                expires_at: datetime) -> None:
        if (not isinstance(activation_id, str) or not SAFE_IDENTIFIER.fullmatch(activation_id) or
                not isinstance(dispatch_id, str) or not SAFE_IDENTIFIER.fullmatch(dispatch_id) or
                type(maximum_provider_calls) is not int or maximum_provider_calls != 3 or
                maximum_cost_usd != Decimal('0.25') or
                not isinstance(maximum_cost_usd, Decimal) or
                not isinstance(expires_at, datetime) or expires_at.tzinfo is None or
                expires_at.utcoffset() is None):
            raise StateError('acceptance budget binding differs from owner authorization')
        epoch = int(expires_at.timestamp())
        partition = {'S': f'ACTIVATION#{activation_id}'}
        dispatch_key = {'PK': partition, 'SK': {'S': f'DISPATCH#{dispatch_id}'}}
        expected = {'PK': partition, 'SK': dispatch_key['SK'],
                    'maximum_cost_microusd': {'N': '250000'},
                    'expires_at': {'N': str(epoch)}}
        aggregate_key = {'PK': partition, 'SK': {'S': 'BUDGET'}}
        try:
            self.client.transact_write_items(TransactItems=[
                {'Put': {'TableName': self.table_name, 'Item': expected,
                         'ConditionExpression': 'attribute_not_exists(PK) AND attribute_not_exists(SK)'}},
                {'Update': {'TableName': self.table_name, 'Key': aggregate_key,
                            'UpdateExpression': 'SET #calls = if_not_exists(#calls, :zero) + :one, '
                                '#reserved = if_not_exists(#reserved, :zero) + :cost, '
                                '#expiry = if_not_exists(#expiry, :expiry)',
                            'ConditionExpression': '(attribute_not_exists(#calls) OR #calls < :max) '
                                'AND (attribute_not_exists(#reserved) OR #reserved <= :remaining) '
                                'AND (attribute_not_exists(#expiry) OR #expiry = :expiry)',
                            'ExpressionAttributeNames': {
                                '#calls': 'calls', '#reserved': 'reserved_microusd',
                                '#expiry': 'expires_at'},
                            'ExpressionAttributeValues': {
                                ':zero': {'N': '0'}, ':one': {'N': '1'},
                                ':cost': {'N': '250000'}, ':max': {'N': '3'},
                                ':remaining': {'N': '4750000'}, ':expiry': {'N': str(epoch)}}}}
            ])
        except Exception as error:
            # Only an identical, already committed dispatch is a safe replay.
            # A missing record may also mean an unknown outcome: fail closed.
            try:
                prior = self.client.get_item(TableName=self.table_name, Key=dispatch_key,
                                             ConsistentRead=True).get('Item')
            except Exception:
                raise StateError('acceptance budget outcome unknown') from error
            if prior == expected:
                return
            raise StateError('acceptance budget exhausted, conflicted or outcome unknown') from error
