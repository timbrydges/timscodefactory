"""Parse a bounded Inspector response as evidence, never as authorization.

An arbitrary caller can supply these bytes. Authentication of a provider call,
one-use budget reservation, and receipt publication are separate future gates.
"""
from __future__ import annotations

import json
from dataclasses import dataclass

from factory_state.model import StateError


@dataclass(frozen=True)
class InspectorAssessment:
    plan_digest: str
    input_digest: str
    contract_digest: str
    verdict: str
    rationale: str
    evidence: tuple[str, ...]
    status: str = 'UNAUTHENTICATED_ASSESSMENT'


def parse_assessment(raw: bytes, request: dict) -> InspectorAssessment:
    if (not isinstance(raw, bytes) or not 0 < len(raw) <= 16384 or
            not isinstance(request, dict) or
            request.get('status') != 'PREPARED_NOT_INVOKED' or
            request.get('model_calls_authorized') != 0 or
            not isinstance(request.get('user'), str)):
        raise StateError('Inspector assessment lacks an exact pending request')

    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise StateError('duplicate Inspector assessment field')
            result[key] = value
        return result

    try:
        material = json.loads(request['user'], object_pairs_hook=unique)
        response = json.loads(raw.decode('utf-8'), object_pairs_hook=unique)
    except (UnicodeDecodeError, ValueError, TypeError) as error:
        raise StateError('Inspector assessment is malformed') from error
    binding = ('plan_digest', 'input_digest', 'contract_digest')
    if (not isinstance(material, dict) or not isinstance(response, dict) or
            set(response) != set(binding) | {'verdict', 'rationale', 'evidence'} or
            any(not isinstance(material.get(key), str) or
                not material[key].startswith('sha256:') or
                len(material[key]) != 71 or
                response.get(key) != material[key] for key in binding) or
            request.get('plan_digest') != material['plan_digest']):
        raise StateError('Inspector assessment differs from exact review binding')
    # Only field names and numeric bounds enter diagnostics, never model text.
    if response.get('verdict') not in ('ACCEPTED', 'REJECTED'):
        raise StateError('Inspector assessment invalid verdict enum')
    rationale = response.get('rationale')
    if not isinstance(rationale, str):
        raise StateError('Inspector assessment rationale must be a string')
    if not 1 <= len(rationale.strip()) <= 2000:
        raise StateError(f'Inspector assessment rationale length={len(rationale.strip())}; allowed=1..2000')
    evidence = response.get('evidence')
    if not isinstance(evidence, list):
        raise StateError('Inspector assessment evidence must be an array')
    if not 1 <= len(evidence) <= 8:
        raise StateError(f'Inspector assessment evidence count={len(evidence)}; allowed=1..8')
    for index, item in enumerate(evidence):
        if not isinstance(item, str):
            raise StateError(f'Inspector assessment evidence[{index}] must be a string')
        if not 1 <= len(item.strip()) <= 500:
            raise StateError(f'Inspector assessment evidence[{index}] length={len(item.strip())}; allowed=1..500')
    return InspectorAssessment(*(response[key] for key in binding),
        response['verdict'], response['rationale'], tuple(response['evidence']))
