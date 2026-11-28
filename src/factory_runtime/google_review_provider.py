"""Credential-owning Google Gemini QA reviewer for development attempts, disabled by default.

The second independent review: after the Anthropic Inspector approves, a Google
model assesses the same review turn as QA. Both must approve. One bounded
generateContent request through a fixed HTTPS route, structured JSON output, no
tools, no cached content and no retry; the response is reduced to the shared
review decision. Response handling follows ``google_qa.parse_response``.
"""
from __future__ import annotations

import asyncio
import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from decimal import Decimal

from .anthropic_provider import AnthropicProviderProtocolError as ReviewProtocolError
from .openai_provider import (
    OpenAIProviderCredentialError, OpenAIProviderDisabledError, OpenAIProviderPricingError,
    ProviderCredentialLease, ProviderHTTPResponse, _aware, _cost_usd, _decision_schema,
    _instructions, _validate_pricing)
from .provider_broker_service import ProviderInvocationResult, ProviderInvoker, ResolvedProviderTarget

GOOGLE_FAMILY = 'google'
GOOGLE_AUDIENCE = 'generativelanguage.googleapis.com'
MODEL = re.compile(r'gemini-[a-z0-9.-]{1,40}')
QA_INSTRUCTIONS = (' You are the QA reviewer after an independent Inspector: look for requirement gaps, '
                   'untested behaviour, regressions and unsafe changes. Do not claim to have executed tests.')


def endpoint_for(model_id):
    if type(model_id) is not str or not MODEL.fullmatch(model_id):
        raise ValueError('approved Gemini model id required')
    return f'https://generativelanguage.googleapis.com/v1beta/models/{model_id}:generateContent'


@dataclass(frozen=True)
class GoogleQAPolicy:
    live_enabled: bool = False
    workload: str = 'task_review'
    timeout_seconds: int = 180
    max_request_bytes: int = 42020
    max_response_bytes: int = 256 * 1024
    max_output_tokens: int = 4096
    max_credential_ttl_seconds: int = 900
    max_pricing_age_seconds: int = 86400

    def __post_init__(self):
        if self.workload != 'task_review' or type(self.live_enabled) is not bool:
            raise ValueError('the Google adapter only reviews, with explicit activation')
        for name, value, low, high in (
                ('timeout_seconds', self.timeout_seconds, 1, 180),
                ('max_request_bytes', self.max_request_bytes, 4096, 1024 * 1024),
                ('max_response_bytes', self.max_response_bytes, 4096, 1024 * 1024),
                ('max_output_tokens', self.max_output_tokens, 1024, 32768),
                ('max_credential_ttl_seconds', self.max_credential_ttl_seconds, 30, 3600),
                ('max_pricing_age_seconds', self.max_pricing_age_seconds, 60, 7 * 86400)):
            if type(value) is not int or not low <= value <= high:
                raise ValueError(f'{name} must be between {low} and {high}')


def _validate_credential(credential, *, policy, now):
    from datetime import timedelta
    if not isinstance(credential, ProviderCredentialLease):
        raise OpenAIProviderCredentialError('provider credential lease is required')
    if credential.provider_family != GOOGLE_FAMILY or credential.audience != GOOGLE_AUDIENCE:
        raise OpenAIProviderCredentialError('provider credential family or audience mismatch')
    token = credential.token
    if not isinstance(token, str) or not 16 <= len(token) <= 256 or any(ord(c) < 33 or ord(c) > 126 for c in token):
        raise OpenAIProviderCredentialError('provider credential token is invalid')
    if not _aware(credential.issued_at) or not _aware(credential.expires_at):
        raise OpenAIProviderCredentialError('provider credential timestamps must be timezone-aware')
    ttl = (credential.expires_at - credential.issued_at).total_seconds()
    if (credential.issued_at > now + timedelta(seconds=30) or credential.expires_at <= now
            or ttl <= 0 or ttl > policy.max_credential_ttl_seconds):
        raise OpenAIProviderCredentialError('provider credential lease is outside its window')


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate field')
        result[key] = value
    return result


def parse_review(payload, model_id, max_output_tokens):
    """(decision, input_tokens, output_tokens) from a generateContent response."""
    try:
        candidates, usage = payload['candidates'], payload['usageMetadata']
        if payload.get('modelVersion') != model_id:
            raise ReviewProtocolError('response model differs', failure_code='model_mismatch')
        if payload.get('promptFeedback', {}).get('blockReason'):
            raise ReviewProtocolError('model declined the review', failure_code='refusal')
        if not isinstance(candidates, list) or len(candidates) != 1:
            raise ReviewProtocolError('one candidate required', failure_code='output_content_invalid')
        finish = candidates[0].get('finishReason')
        if finish == 'MAX_TOKENS':
            raise ReviewProtocolError('review ran out of output tokens', failure_code='output_token_limit')
        if finish in ('SAFETY', 'RECITATION', 'PROHIBITED_CONTENT', 'BLOCKLIST', 'SPII'):
            raise ReviewProtocolError('model declined the review', failure_code='refusal')
        if finish != 'STOP' or candidates[0]['content'].get('role') != 'model':
            raise ReviewProtocolError('review did not complete', failure_code='response_incomplete')
        parts = candidates[0]['content']['parts']
        if (not isinstance(parts, list) or len(parts) != 1 or not isinstance(parts[0], dict)
                or set(parts[0]) - {'text', 'thoughtSignature'} or not isinstance(parts[0].get('text'), str)):
            raise ReviewProtocolError('exactly one text part required', failure_code='output_text_count_invalid')
        counts = [usage['promptTokenCount'], usage.get('candidatesTokenCount', 0),
                  usage.get('thoughtsTokenCount', 0), usage['totalTokenCount']]
        if (any(type(n) is not int or n < 0 for n in counts) or sum(counts[:3]) != counts[3]
                or counts[1] + counts[2] > max_output_tokens
                or usage.get('cachedContentTokenCount', 0) != 0 or usage.get('toolUsePromptTokenCount', 0) != 0):
            raise ReviewProtocolError('usage invalid', failure_code='usage_invalid')
    except ReviewProtocolError:
        raise
    except (KeyError, TypeError, AttributeError):
        raise ReviewProtocolError('response malformed', failure_code='structured_output_invalid') from None
    try:
        decision = json.loads(parts[0]['text'], object_pairs_hook=_unique)
    except ValueError:
        raise ReviewProtocolError('review is not JSON', failure_code='output_json_invalid') from None
    if (not isinstance(decision, dict) or set(decision) != {'review_input_digest', 'verdict', 'findings'}
            or not isinstance(decision['review_input_digest'], str)
            or decision['verdict'] not in ('APPROVE', 'REJECT')
            or not isinstance(decision['findings'], list)
            or any(not isinstance(v, str) for v in decision['findings'])):
        raise ReviewProtocolError('structured review has invalid fields', failure_code='review_fields_invalid')
    # Thinking tokens are billed as output.
    return decision, counts[0], counts[1] + counts[2]


class GoogleQAReviewInvoker(ProviderInvoker):
    """Strict Gemini QA reviewer behind the broker ProviderInvoker seam."""

    def __init__(self, credential_source, pricing_source, transport, *, policy=None):
        self.credential_source, self.pricing_source, self.transport = credential_source, pricing_source, transport
        self.policy = policy or GoogleQAPolicy()
        self.invocation_count = 0
        self.last_response_evidence = {}

    def request_body(self, turn):
        payload = {
            'systemInstruction': {'parts': [{'text': _instructions('task_review') + QA_INSTRUCTIONS}]},
            'contents': [{'role': 'user', 'parts': [{'text': json.dumps(
                turn, sort_keys=True, separators=(',', ':'), ensure_ascii=False)}]}],
            'generationConfig': {'candidateCount': 1, 'maxOutputTokens': self.policy.max_output_tokens,
                'responseMimeType': 'application/json', 'responseJsonSchema': _decision_schema('task_review'),
                'thinkingConfig': {'thinkingLevel': 'LOW', 'includeThoughts': False}},
        }
        return json.dumps(payload, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode('utf-8')

    async def invoke(self, *, target, turn, max_cost_usd, decision_schema_version):
        self.last_response_evidence = {}
        if not self.policy.live_enabled:
            raise OpenAIProviderDisabledError('live Google provider traffic is disabled by policy')
        if not isinstance(target, ResolvedProviderTarget) or target.provider_family != GOOGLE_FAMILY:
            raise ReviewProtocolError('Google invoker received a non-Google target')
        endpoint = endpoint_for(target.model_id)
        if decision_schema_version != '1' or not isinstance(turn, dict):
            raise ReviewProtocolError('review turn and schema version 1 required')
        if not isinstance(max_cost_usd, Decimal) or not max_cost_usd.is_finite() or max_cost_usd <= 0:
            raise OpenAIProviderPricingError('max_cost_usd must be a positive finite Decimal')
        quote = await self.pricing_source.quote(target=target)
        _validate_pricing(quote, target=target, policy=self.policy, now=datetime.now(timezone.utc))
        body = self.request_body(turn)
        if len(body) > self.policy.max_request_bytes:
            raise ReviewProtocolError('request exceeds byte cap', failure_code='request_byte_limit')
        worst = (Decimal(len(body)) * quote.input_usd_per_million_tokens
                 + Decimal(self.policy.max_output_tokens) * quote.output_usd_per_million_tokens) / Decimal(1_000_000)
        if worst > max_cost_usd:
            raise OpenAIProviderPricingError('worst-case QA cost exceeds the stage cap')
        credential = await self.credential_source.issue(target=target)
        _validate_credential(credential, policy=self.policy, now=datetime.now(timezone.utc))
        headers = {'x-goog-api-key': credential.token, 'content-type': 'application/json',
                   'accept': 'application/json'}
        try:
            response = await asyncio.wait_for(self.transport.post_json(
                endpoint=endpoint, headers=headers, body=body,
                timeout_seconds=self.policy.timeout_seconds), timeout=self.policy.timeout_seconds)
        except asyncio.TimeoutError:
            raise ReviewProtocolError('QA review timed out', failure_code='timeout') from None
        finally:
            credential = None
            headers = {}
        if not isinstance(response, ProviderHTTPResponse):
            raise ReviewProtocolError('transport returned an invalid response')
        if response.status_code != 200:
            raise ReviewProtocolError('provider returned an HTTP error', failure_code='http_error')
        if not isinstance(response.body, bytes) or len(response.body) > self.policy.max_response_bytes:
            raise ReviewProtocolError('response exceeds byte cap', failure_code='response_byte_limit')
        try:
            payload = json.loads(response.body.decode('utf-8'), object_pairs_hook=_unique)
        except (UnicodeDecodeError, ValueError):
            raise ReviewProtocolError('response is not JSON', failure_code='structured_output_invalid') from None
        if not isinstance(payload, dict):
            raise ReviewProtocolError('response must be an object', failure_code='structured_output_invalid')
        usage = payload.get('usageMetadata') if isinstance(payload.get('usageMetadata'), dict) else {}
        self.last_response_evidence = {'model_matches': payload.get('modelVersion') == target.model_id,
            **{k: usage[k] for k in ('promptTokenCount', 'candidatesTokenCount', 'thoughtsTokenCount')
               if type(usage.get(k)) is int}}
        decision, input_tokens, output_tokens = parse_review(payload, target.model_id, self.policy.max_output_tokens)
        cost = _cost_usd(quote, input_tokens, output_tokens)
        if cost > max_cost_usd:
            raise OpenAIProviderPricingError('reported usage exceeds the stage cap')
        self.invocation_count += 1
        return ProviderInvocationResult(decision=decision, input_tokens=input_tokens,
                                        output_tokens=output_tokens, cost_usd=cost)
