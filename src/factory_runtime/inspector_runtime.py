"""Single-call authenticated Inspector runtime for the acceptance review.

The service reserves the full conservative Inspector budget before one Bedrock
Converse call. Any transport error or malformed response consumes the single
reservation, so callers cannot retry an uncertain provider outcome. A sealed
decision can authorize the isolated reviewer signer only when it is ACCEPTED
and bound to the exact intake plan digests.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from decimal import Decimal
from typing import Any

from factory_state.model import StateError
from .inspector_assessment import parse_assessment
from .inspector_budget import (
    MAX_OUTPUT_TOKENS, RESERVED_INPUT_TOKENS, InspectorBudgetStore, PROFILE)
from .receipt_transport import receipt_plan_digest

_DECISION_SEAL = object()
MAX_RESPONSE_BYTES = 16384


@dataclass(frozen=True)
class AuthenticatedInspectorDecision:
    plan_digest: str
    input_digest: str
    contract_digest: str
    verdict: str
    rationale: str
    evidence: tuple[str, ...]
    model_id: str
    input_tokens: int
    output_tokens: int
    total_tokens: int
    request_digest: str
    response_digest: str
    actual_cost_usd: str
    _seal: object

    def __post_init__(self):
        if self._seal is not _DECISION_SEAL:
            raise StateError('Inspector decision is not runtime-authenticated')


def validate_authenticated_decision(decision, plan) -> AuthenticatedInspectorDecision:
    if not isinstance(decision, AuthenticatedInspectorDecision) or decision._seal is not _DECISION_SEAL:
        raise StateError('reviewer publication requires an authenticated Inspector decision')
    if (decision.verdict != 'ACCEPTED' or
            decision.model_id != PROFILE or
            decision.plan_digest != receipt_plan_digest(plan) or
            decision.input_digest != plan.request.input_digest or
            decision.contract_digest != plan.request.contract_digest or
            not 0 <= decision.input_tokens <= RESERVED_INPUT_TOKENS or
            not 0 <= decision.output_tokens <= MAX_OUTPUT_TOKENS or
            decision.total_tokens != decision.input_tokens + decision.output_tokens):
        raise StateError('authenticated Inspector decision differs from reviewed plan')
    return decision


class InspectorReviewRuntime:
    def __init__(self, bedrock_client: Any, budget: InspectorBudgetStore):
        config = getattr(getattr(bedrock_client, 'meta', None), 'config', None)
        endpoint = getattr(getattr(bedrock_client, 'meta', None), 'endpoint_url', None)
        if (config is None or endpoint != 'https://bedrock-runtime.ca-central-1.amazonaws.com' or
                config.retries.get('total_max_attempts') != 1):
            raise StateError('Inspector runtime requires Canada Bedrock with retries disabled')
        if not isinstance(budget, InspectorBudgetStore):
            raise StateError('Inspector runtime requires the isolated budget store')
        self.client, self.budget = bedrock_client, budget

    @staticmethod
    def _material(request: dict) -> dict:
        if not isinstance(request, dict) or not isinstance(request.get('user'), str):
            raise StateError('Inspector runtime request is malformed')
        try:
            material = json.loads(request['user'])
        except (TypeError, ValueError) as error:
            raise StateError('Inspector runtime request material is malformed') from error
        if (not isinstance(material, dict) or
                not isinstance(material.get('activation_id'), str) or
                request.get('plan_digest') != material.get('plan_digest')):
            raise StateError('Inspector runtime request binding differs')
        return material

    def review(self, *, request: dict, plan, policy: dict, now) -> AuthenticatedInspectorDecision:
        material = self._material(request)
        if (request.get('status') != 'PREPARED_NOT_INVOKED' or
                request.get('model_calls_authorized') != 0 or
                request.get('plan_digest') != receipt_plan_digest(plan) or
                material.get('input_digest') != plan.request.input_digest or
                material.get('contract_digest') != plan.request.contract_digest or
                not isinstance(request.get('system'), str) or not request['system'].strip()):
            raise StateError('Inspector runtime request differs from exact intake plan')

        assessment_schema = {
            'type': 'object',
            'properties': {
                'plan_digest': {'type': 'string'},
                'input_digest': {'type': 'string'},
                'contract_digest': {'type': 'string'},
                'verdict': {'type': 'string', 'enum': ['ACCEPTED', 'REJECTED']},
                'rationale': {'type': 'string'},
                'evidence': {'type': 'array', 'items': {'type': 'string'},
                             'minItems': 1},
            },
            'required': ['plan_digest', 'input_digest', 'contract_digest',
                         'verdict', 'rationale', 'evidence'],
            'additionalProperties': False,
        }
        provider_request = {
            'modelId': PROFILE,
            'system': [{'text': request['system']}],
            'messages': [{'role': 'user', 'content': [{'text': request['user']}]}],
            'inferenceConfig': {'maxTokens': MAX_OUTPUT_TOKENS, 'temperature': 0},
            'toolConfig': {
                'tools': [{
                    'toolSpec': {
                        'name': 'submit_inspector_assessment',
                        'description': (
                            'Return the exact bounded Inspector assessment. '
                            'This tool does not sign, publish, or authorize anything.'),
                        'inputSchema': {'json': assessment_schema},
                    }
                }],
                'toolChoice': {'tool': {'name': 'submit_inspector_assessment'}},
            },
        }
        request_bytes = json.dumps(
            provider_request, sort_keys=True, separators=(',', ':'),
            ensure_ascii=True).encode('utf-8')
        reservation = self.budget.reserve(
            activation_id=material['activation_id'],
            plan_digest=request['plan_digest'],
            request_bytes=request_bytes, policy=policy, now=now)
        if reservation.get('provider_calls_remaining') != 0:
            raise StateError('Inspector reservation did not consume the only call')

        # Exactly one provider call. The boto client must have retries disabled.
        # Any exception after the durable reservation is terminal for this activation.
        response = self.client.converse(**provider_request)
        try:
            content = response['output']['message']['content']
            usage = response['usage']
            if (response.get('stopReason') != 'tool_use' or
                    not isinstance(content, list) or len(content) != 1 or
                    not isinstance(content[0], dict) or set(content[0]) != {'toolUse'} or
                    not isinstance(content[0]['toolUse'], dict)):
                raise ValueError('invalid content')
            tool = content[0]['toolUse']
            if (tool.get('name') != 'submit_inspector_assessment' or
                    not isinstance(tool.get('toolUseId'), str) or
                    not isinstance(tool.get('input'), dict)):
                raise ValueError('invalid tool use')
            input_tokens = usage['inputTokens']
            output_tokens = usage['outputTokens']
            total_tokens = usage['totalTokens']
            if (any(type(value) is not int or value < 0
                    for value in (input_tokens, output_tokens, total_tokens)) or
                    input_tokens > RESERVED_INPUT_TOKENS or
                    output_tokens > MAX_OUTPUT_TOKENS or
                    total_tokens != input_tokens + output_tokens):
                raise ValueError('invalid usage')
        except (KeyError, TypeError, ValueError) as error:
            raise StateError('Inspector provider response or usage is malformed') from error

        raw = json.dumps(tool['input'], sort_keys=True, separators=(',', ':')).encode('utf-8')
        if not 0 < len(raw) <= MAX_RESPONSE_BYTES:
            raise StateError('Inspector provider response exceeds bounded size')
        assessment = parse_assessment(raw, request)
        actual = ((Decimal(input_tokens) * Decimal('3.00') +
                   Decimal(output_tokens) * Decimal('15.00')) / Decimal(1000000))
        if actual > Decimal(reservation['reserved_cost_usd']) or actual >= Decimal('0.25'):
            raise StateError('Inspector provider usage exceeds reserved budget')
        return AuthenticatedInspectorDecision(
            assessment.plan_digest, assessment.input_digest,
            assessment.contract_digest, assessment.verdict,
            assessment.rationale, assessment.evidence, PROFILE,
            input_tokens, output_tokens, total_tokens,
            'sha256:' + hashlib.sha256(request_bytes).hexdigest(),
            'sha256:' + hashlib.sha256(raw).hexdigest(),
            str(actual), _DECISION_SEAL)
