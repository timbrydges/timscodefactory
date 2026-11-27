"""Credential-owning Anthropic Messages reviewer, disabled by default.

The independent reviewer for development attempts: an OpenAI builder's proposal
is reviewed by a different provider family. Like the OpenAI adapter it sits
behind the ProviderInvoker seam, sends exactly one bounded request through a
fixed HTTPS route with no SDK, retry or redirect (an unknown-outcome paid
request is never replayed), and returns only the normalized review decision.

The request asks for the shared task_review JSON schema through structured
outputs (``output_config.format``), with no tools and no cache writes, so the
worst-case cost is bounded by request bytes and ``max_tokens`` at the pinned
price. Thinking tokens are billed as output and fall inside ``max_tokens``.
"""

from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from typing import Any

from .openai_provider import (
    OpenAIProviderCredentialError,
    OpenAIProviderDisabledError,
    OpenAIProviderPricingError,
    OpenAIProviderProtocolError,
    ProviderCredentialLease,
    ProviderHTTPResponse,
    _aware,
    _cost_usd,
    _decision_schema,
    _instructions,
    _validate_pricing,
)
from .provider_broker_service import ProviderInvocationResult, ProviderInvoker, ResolvedProviderTarget

ANTHROPIC_FAMILY = 'anthropic'
ANTHROPIC_ENDPOINT = 'https://api.anthropic.com/v1/messages'
ANTHROPIC_AUDIENCE = 'api.anthropic.com'
ANTHROPIC_VERSION = '2026-10-21'
_EFFORTS = frozenset({'low', 'medium', 'high'})


class AnthropicProviderProtocolError(OpenAIProviderProtocolError):
    """Same bounded failure codes as the OpenAI adapter; never carries provider text."""


@dataclass(frozen=True)
class AnthropicReviewPolicy:
    live_enabled: bool = False
    workload: str = 'task_review'
    endpoint: str = ANTHROPIC_ENDPOINT
    timeout_seconds: int = 180
    max_request_bytes: int = 42020
    max_response_bytes: int = 256 * 1024
    max_output_tokens: int = 4096
    max_credential_ttl_seconds: int = 900
    max_pricing_age_seconds: int = 86400
    effort: str = 'low'

    def __post_init__(self):
        if self.workload != 'task_review':
            raise ValueError('the Anthropic adapter only reviews')
        if type(self.live_enabled) is not bool:
            raise ValueError('live_enabled must be boolean')
        if self.endpoint != ANTHROPIC_ENDPOINT:
            raise ValueError('Anthropic endpoint must be the exact /v1/messages endpoint')
        for name, value, low, high in (
                ('timeout_seconds', self.timeout_seconds, 1, 180),
                ('max_request_bytes', self.max_request_bytes, 4096, 1024 * 1024),
                ('max_response_bytes', self.max_response_bytes, 4096, 1024 * 1024),
                ('max_output_tokens', self.max_output_tokens, 1024, 32768),
                ('max_credential_ttl_seconds', self.max_credential_ttl_seconds, 30, 3600),
                ('max_pricing_age_seconds', self.max_pricing_age_seconds, 60, 7 * 86400)):
            if type(value) is not int or not low <= value <= high:
                raise ValueError(f'{name} must be between {low} and {high}')
        if self.effort not in _EFFORTS:
            raise ValueError('effort is not an approved value')


def _validate_credential(credential, *, policy, now):
    if not isinstance(credential, ProviderCredentialLease):
        raise OpenAIProviderCredentialError('provider credential lease is required')
    if credential.provider_family != ANTHROPIC_FAMILY or credential.audience != ANTHROPIC_AUDIENCE:
        raise OpenAIProviderCredentialError('provider credential family or audience mismatch')
    token = credential.token
    if not isinstance(token, str) or len(token) < 16 or any(ord(c) < 33 or ord(c) > 126 for c in token):
        raise OpenAIProviderCredentialError('provider credential token is invalid')
    if not _aware(credential.issued_at) or not _aware(credential.expires_at):
        raise OpenAIProviderCredentialError('provider credential timestamps must be timezone-aware')
    ttl = (credential.expires_at - credential.issued_at).total_seconds()
    if (credential.issued_at > now + timedelta(seconds=30) or credential.expires_at <= now
            or ttl <= 0 or ttl > policy.max_credential_ttl_seconds):
        raise OpenAIProviderCredentialError('provider credential lease is outside its window')


def _response_evidence(payload, requested_model):
    """Bounded scalars only; never provider text, identifiers or errors."""
    evidence = {'model_matches': payload.get('model') == requested_model}
    if payload.get('stop_reason') in ('end_turn', 'max_tokens', 'refusal', 'stop_sequence',
                                      'tool_use', 'pause_turn'):
        evidence['stop_reason'] = payload['stop_reason']
    usage = payload.get('usage')
    if isinstance(usage, dict):
        for name in ('input_tokens', 'output_tokens'):
            value = usage.get(name)
            if type(value) is int and 0 <= value <= 1_000_000_000:
                evidence[name] = value
    return evidence


def _extract_review(payload):
    stop = payload.get('stop_reason')
    if stop == 'max_tokens':
        raise AnthropicProviderProtocolError('review ran out of output tokens', failure_code='output_token_limit')
    if stop == 'refusal':
        raise AnthropicProviderProtocolError('model declined the review', failure_code='refusal')
    if stop != 'end_turn' or payload.get('type') != 'message':
        raise AnthropicProviderProtocolError('review did not complete', failure_code='response_incomplete')
    content = payload.get('content')
    if not isinstance(content, list) or any(not isinstance(b, dict) for b in content):
        raise AnthropicProviderProtocolError('review content is invalid', failure_code='output_content_invalid')
    # Thinking blocks (empty by default) are ignored; tools are never offered.
    if any(b.get('type') not in ('text', 'thinking', 'redacted_thinking') for b in content):
        raise AnthropicProviderProtocolError('unexpected content block', failure_code='output_content_invalid')
    texts = [b.get('text') for b in content if b.get('type') == 'text']
    if len(texts) != 1 or not isinstance(texts[0], str):
        raise AnthropicProviderProtocolError('exactly one text block required', failure_code='output_text_count_invalid')
    try:
        parsed = json.loads(texts[0])
    except json.JSONDecodeError:
        raise AnthropicProviderProtocolError('review is not JSON', failure_code='output_json_invalid') from None
    if (not isinstance(parsed, dict) or set(parsed) != {'review_input_digest', 'verdict', 'findings'}
            or not isinstance(parsed['review_input_digest'], str)
            or parsed['verdict'] not in ('APPROVE', 'REJECT')
            or not isinstance(parsed['findings'], list)
            or any(not isinstance(v, str) for v in parsed['findings'])):
        raise AnthropicProviderProtocolError('structured review has invalid fields', failure_code='review_fields_invalid')
    return parsed


def _usage(payload):
    usage = payload.get('usage')
    if not isinstance(usage, dict):
        raise AnthropicProviderProtocolError('usage is missing', failure_code='usage_invalid')
    tokens = []
    for name in ('input_tokens', 'output_tokens'):
        value = usage.get(name)
        if type(value) is not int or value < 0:
            raise AnthropicProviderProtocolError('usage is invalid', failure_code='usage_invalid')
        tokens.append(value)
    # No cache_control is sent; any cache write or read would break the exact cost bound.
    for name in ('cache_creation_input_tokens', 'cache_read_input_tokens'):
        if usage.get(name) not in (None, 0):
            raise AnthropicProviderProtocolError('unexpected cache usage', failure_code='usage_invalid')
    return tokens[0], tokens[1]


class AnthropicMessagesReviewInvoker(ProviderInvoker):
    """Strict Anthropic Messages reviewer behind the broker ProviderInvoker seam."""

    def __init__(self, credential_source, pricing_source, transport, *, policy=None):
        self.credential_source = credential_source
        self.pricing_source = pricing_source
        self.transport = transport
        self.policy = policy or AnthropicReviewPolicy()
        self.invocation_count = 0
        self.last_response_evidence = {}

    def request_body(self, model_id, turn):
        payload = {
            'model': model_id,
            'max_tokens': self.policy.max_output_tokens,
            'system': _instructions('task_review'),
            'messages': [{'role': 'user', 'content': json.dumps(
                turn, sort_keys=True, separators=(',', ':'), ensure_ascii=False)}],
            'output_config': {'effort': self.policy.effort,
                              'format': {'type': 'json_schema', 'schema': _decision_schema('task_review')}},
        }
        return json.dumps(payload, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode('utf-8')

    async def invoke(self, *, target, turn, max_cost_usd, decision_schema_version):
        self.last_response_evidence = {}
        if not self.policy.live_enabled:
            raise OpenAIProviderDisabledError('live Anthropic provider traffic is disabled by policy')
        if not isinstance(target, ResolvedProviderTarget) or target.provider_family != ANTHROPIC_FAMILY:
            raise AnthropicProviderProtocolError('Anthropic invoker received a non-Anthropic target')
        if decision_schema_version != '1' or not isinstance(turn, dict):
            raise AnthropicProviderProtocolError('review turn and schema version 1 required')
        if not isinstance(max_cost_usd, Decimal) or not max_cost_usd.is_finite() or max_cost_usd <= 0:
            raise OpenAIProviderPricingError('max_cost_usd must be a positive finite Decimal')
        quote = await self.pricing_source.quote(target=target)
        _validate_pricing(quote, target=target, policy=self.policy, now=datetime.now(timezone.utc))
        body = self.request_body(target.model_id, turn)
        if len(body) > self.policy.max_request_bytes:
            raise AnthropicProviderProtocolError('request exceeds byte cap', failure_code='request_byte_limit')
        # UTF-8 bytes bound input tokens; max_tokens bounds output including thinking.
        worst = (Decimal(len(body)) * quote.input_usd_per_million_tokens
                 + Decimal(self.policy.max_output_tokens) * quote.output_usd_per_million_tokens) / Decimal(1_000_000)
        if worst > max_cost_usd:
            raise OpenAIProviderPricingError('worst-case review cost exceeds the stage cap')
        credential = await self.credential_source.issue(target=target)
        _validate_credential(credential, policy=self.policy, now=datetime.now(timezone.utc))
        headers = {'x-api-key': credential.token, 'anthropic-version': ANTHROPIC_VERSION,
                   'content-type': 'application/json', 'accept': 'application/json'}
        try:
            response = await asyncio.wait_for(self.transport.post_json(
                endpoint=self.policy.endpoint, headers=headers, body=body,
                timeout_seconds=self.policy.timeout_seconds), timeout=self.policy.timeout_seconds)
        except asyncio.TimeoutError:
            raise AnthropicProviderProtocolError('review timed out', failure_code='timeout') from None
        finally:
            credential = None
            headers = {}
        if not isinstance(response, ProviderHTTPResponse):
            raise AnthropicProviderProtocolError('transport returned an invalid response')
        if response.status_code != 200:
            raise AnthropicProviderProtocolError('provider returned an HTTP error', failure_code='http_error')
        if not isinstance(response.body, bytes) or len(response.body) > self.policy.max_response_bytes:
            raise AnthropicProviderProtocolError('response exceeds byte cap', failure_code='response_byte_limit')
        try:
            payload = json.loads(response.body.decode('utf-8'))
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise AnthropicProviderProtocolError('response is not JSON', failure_code='structured_output_invalid') from None
        if not isinstance(payload, dict):
            raise AnthropicProviderProtocolError('response must be an object', failure_code='structured_output_invalid')
        self.last_response_evidence = _response_evidence(payload, target.model_id)
        if payload.get('model') != target.model_id:
            raise AnthropicProviderProtocolError('response model differs', failure_code='model_mismatch')
        decision = _extract_review(payload)
        input_tokens, output_tokens = _usage(payload)
        cost = _cost_usd(quote, input_tokens, output_tokens)
        if cost > max_cost_usd:
            raise OpenAIProviderPricingError('reported usage exceeds the stage cap')
        self.invocation_count += 1
        return ProviderInvocationResult(decision=decision, input_tokens=input_tokens,
                                        output_tokens=output_tokens, cost_usd=cost)
