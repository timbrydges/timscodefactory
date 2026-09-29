"""Single-use Inspector reservation; never retries an uncertain model outcome.

This is a preparation primitive. No caller is enabled or permitted to invoke
Bedrock until the independent Inspector runtime and receipt publisher exist.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timedelta
from decimal import Decimal
from pathlib import Path
from typing import Any

from factory_state.model import SAFE_IDENTIFIER, StateError

PROFILE = 'global.anthropic.claude-sonnet-5-5'
TABLE = 'tims-factory-acceptance-budget'


def _price(quote: dict, *, now: datetime, input_tokens: int,
           maximum_output_tokens: int) -> Decimal:
    if (not isinstance(quote, dict) or quote.get('schema_version') != '1.0' or
            quote.get('status') != 'PREPARED_NOT_ACTIVATED' or
            quote.get('source') != 'https://aws.amazon.com/bedrock/pricing/' or
            quote.get('source_region') != 'ca-central-1' or
            quote.get('inference_scope') != 'Global Cross-region Inference' or
            quote.get('model_id') != PROFILE or
            quote.get('financial_scope') != 'separate_from_openai_builder_acceptance' or
            quote.get('maximum_total_cost_usd') != '0.25' or
            type(quote.get('maximum_provider_calls')) is not int or
            quote['maximum_provider_calls'] != 1 or
            type(quote.get('maximum_input_tokens')) is not int or
            quote['maximum_input_tokens'] != 42020 or
            type(quote.get('maximum_output_tokens')) is not int or
            quote['maximum_output_tokens'] != 4096 or
            type(input_tokens) is not int or not 0 < input_tokens <= 42020 or
            type(maximum_output_tokens) is not int or maximum_output_tokens != 4096 or
            not isinstance(now, datetime) or now.tzinfo is None or
            now.utcoffset() is None):
        raise StateError('Inspector quote or token bounds differ')
    try:
        observed = datetime.fromisoformat(quote['observed_at'].replace('Z', '+00:00'))
        expires = datetime.fromisoformat(quote['expires_at'].replace('Z', '+00:00'))
        input_rate = Decimal(quote['input_usd_per_million_tokens'])
        output_rate = Decimal(quote['output_usd_per_million_tokens'])
        maximum = Decimal(quote['conservative_maximum_cost_usd'])
    except (KeyError, ValueError, TypeError) as error:
        raise StateError('Inspector price quote is invalid') from error
    if (not observed <= now < expires or expires <= observed or
            expires - observed > timedelta(hours=24) or
            input_rate != Decimal('2.00') or output_rate != Decimal('10.00') or
            maximum != Decimal('0.12500')):
        raise StateError('Inspector price quote is stale or differs')
    bound = ((Decimal(input_tokens) * input_rate +
              Decimal(maximum_output_tokens) * output_rate) / Decimal(1000000))
    if bound > maximum or bound > Decimal('0.25'):
        raise StateError('Inspector token cost exceeds independent allowance')
    return bound


@dataclass
class InspectorBudgetStore:
    table_name: str
    client: Any

    def __post_init__(self) -> None:
        if self.table_name != TABLE:
            raise StateError('Inspector reservation requires the isolated acceptance table')

    def reserve(self, *, activation_id: str, plan_digest: str,
                request_bytes: bytes, input_tokens: int,
                maximum_output_tokens: int, quote: dict, now: datetime) -> dict:
        if (not isinstance(activation_id, str) or
                not SAFE_IDENTIFIER.fullmatch(activation_id) or
                not isinstance(plan_digest, str) or len(plan_digest) != 71 or
                not plan_digest.startswith('sha256:') or
                any(c not in '0123456789abcdef' for c in plan_digest[7:]) or
                not isinstance(request_bytes, bytes) or
                not 0 < len(request_bytes) <= 42020):
            raise StateError('Inspector reservation binding differs')
        bound = _price(quote, now=now, input_tokens=input_tokens,
                       maximum_output_tokens=maximum_output_tokens)
        item = {'PK': {'S': 'INSPECTOR#' + activation_id},
                'SK': {'S': 'BUDGET'},
                'plan_digest': {'S': plan_digest},
                'request_digest': {'S': 'sha256:' + hashlib.sha256(request_bytes).hexdigest()},
                'model_id': {'S': PROFILE},
                'maximum_cost_microusd': {'N': '250000'},
                'input_tokens': {'N': str(input_tokens)},
                'maximum_output_tokens': {'N': '4096'},
                'quoted_cost_microusd': {'N': str(int(bound * 1000000))},
                'quote_digest': {'S': 'sha256:' + hashlib.sha256(
                    json.dumps(quote, sort_keys=True, separators=(',', ':')).encode()).hexdigest()}}
        try:
            self.client.put_item(TableName=self.table_name, Item=item,
                ConditionExpression='attribute_not_exists(PK) AND attribute_not_exists(SK)')
        except Exception as error:
            # A committed record, an uncertain response, and a different
            # request all have the same outcome: no further invocation.
            raise StateError('Inspector call already reserved or outcome unknown') from error
        return {'status': 'RESERVED_NOT_INVOKED', 'plan_digest': plan_digest,
                'request_digest': item['request_digest']['S'],
                'maximum_cost_usd': '0.25', 'provider_calls_remaining': 0}
