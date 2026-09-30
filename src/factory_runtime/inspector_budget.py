"""Single-use Inspector reservation with a conservative no-CountTokens bound.

Claude Sonnet 5.5 has no supported exact token-counting path in this commercial
account. The runtime therefore reserves a fixed 100,000 input-token allowance
for any request up to 42,020 bytes, plus 4,096 output tokens. At the locked
price this reserves USD 0.24096, below the independent USD 0.25 call cap.

This is still a preparation primitive. No caller is enabled or permitted to
invoke Bedrock until the independent Inspector runtime and reviewer publisher
exist.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timedelta
from decimal import Decimal
from typing import Any

from factory_state.model import SAFE_IDENTIFIER, StateError

PROFILE = 'global.anthropic.claude-sonnet-5-5'
TABLE = 'tims-factory-acceptance-budget'
MAX_REQUEST_BYTES = 42020
RESERVED_INPUT_TOKENS = 100000
MAX_OUTPUT_TOKENS = 4096
MAX_COST = Decimal('0.25')
RESERVED_COST = Decimal('0.24096')


def _price(policy: dict, *, now: datetime) -> Decimal:
    if (not isinstance(policy, dict) or policy.get('schema_version') != '1.0' or
            policy.get('status') != 'PREPARED_NOT_ACTIVATED' or
            policy.get('model_id') != PROFILE or
            policy.get('source_region') != 'ca-central-1' or
            policy.get('price_quote') !=
                'factory/evidence/acceptance-inspector-pricing-2026-09-29.json' or
            policy.get('input_accounting_method') !=
                'fixed_conservative_reservation_after_counttokens_unavailable' or
            policy.get('maximum_total_cost_usd') != '0.25' or
            type(policy.get('maximum_provider_calls')) is not int or
            policy['maximum_provider_calls'] != 1 or
            type(policy.get('maximum_request_bytes')) is not int or
            policy['maximum_request_bytes'] != MAX_REQUEST_BYTES or
            type(policy.get('reserved_input_tokens')) is not int or
            policy['reserved_input_tokens'] != RESERVED_INPUT_TOKENS or
            type(policy.get('maximum_output_tokens')) is not int or
            policy['maximum_output_tokens'] != MAX_OUTPUT_TOKENS or
            policy.get('conservative_maximum_cost_usd') != str(RESERVED_COST) or
            not isinstance(policy.get('counttokens_observation'), dict) or
            policy['counttokens_observation'].get('model_calls') != 0 or
            policy['counttokens_observation'].get('task_material_sent') is not False or
            not isinstance(now, datetime) or now.tzinfo is None or
            now.utcoffset() is None):
        raise StateError('Inspector conservative budget policy differs')
    try:
        observed = datetime.fromisoformat(policy['observed_at'].replace('Z', '+00:00'))
        expires = datetime.fromisoformat(policy['expires_at'].replace('Z', '+00:00'))
        input_rate = Decimal(policy['input_usd_per_million_tokens'])
        output_rate = Decimal(policy['output_usd_per_million_tokens'])
    except (KeyError, ValueError, TypeError) as error:
        raise StateError('Inspector conservative budget policy is invalid') from error
    bound = ((Decimal(RESERVED_INPUT_TOKENS) * input_rate +
              Decimal(MAX_OUTPUT_TOKENS) * output_rate) / Decimal(1000000))
    if (not observed <= now < expires or expires <= observed or
            expires - observed > timedelta(hours=24) or
            input_rate != Decimal('2.00') or output_rate != Decimal('10.00') or
            bound != RESERVED_COST or bound >= MAX_COST):
        raise StateError('Inspector conservative budget policy is stale or unsafe')
    return bound


@dataclass
class InspectorBudgetStore:
    table_name: str
    client: Any

    def __post_init__(self) -> None:
        if self.table_name != TABLE:
            raise StateError('Inspector reservation requires the isolated acceptance table')

    def reserve(self, *, activation_id: str, plan_digest: str,
                request_bytes: bytes, policy: dict, now: datetime) -> dict:
        if (not isinstance(activation_id, str) or
                not SAFE_IDENTIFIER.fullmatch(activation_id) or
                not isinstance(plan_digest, str) or len(plan_digest) != 71 or
                not plan_digest.startswith('sha256:') or
                any(c not in '0123456789abcdef' for c in plan_digest[7:]) or
                not isinstance(request_bytes, bytes) or
                not 0 < len(request_bytes) <= MAX_REQUEST_BYTES):
            raise StateError('Inspector reservation binding differs')
        bound = _price(policy, now=now)
        item = {'PK': {'S': 'INSPECTOR#' + activation_id},
                'SK': {'S': 'BUDGET'},
                'plan_digest': {'S': plan_digest},
                'request_digest': {'S': 'sha256:' + hashlib.sha256(request_bytes).hexdigest()},
                'model_id': {'S': PROFILE},
                'maximum_cost_microusd': {'N': '250000'},
                'reserved_input_tokens': {'N': str(RESERVED_INPUT_TOKENS)},
                'maximum_output_tokens': {'N': str(MAX_OUTPUT_TOKENS)},
                'reserved_cost_microusd': {'N': str(int(bound * 1000000))},
                'input_accounting_method': {'S':
                    'fixed_conservative_reservation_after_counttokens_unavailable'},
                'policy_digest': {'S': 'sha256:' + hashlib.sha256(
                    json.dumps(policy, sort_keys=True, separators=(',', ':')).encode()).hexdigest()}}
        try:
            self.client.put_item(TableName=self.table_name, Item=item,
                ConditionExpression='attribute_not_exists(PK) AND attribute_not_exists(SK)')
        except Exception as error:
            # A committed record, an uncertain response, and a different
            # request all have the same outcome: no further invocation.
            raise StateError('Inspector call already reserved or outcome unknown') from error
        return {'status': 'RESERVED_NOT_INVOKED', 'plan_digest': plan_digest,
                'request_digest': item['request_digest']['S'],
                'maximum_cost_usd': '0.25',
                'reserved_cost_usd': str(bound),
                'reserved_input_tokens': RESERVED_INPUT_TOKENS,
                'maximum_output_tokens': MAX_OUTPUT_TOKENS,
                'provider_calls_remaining': 0}
