"""Isolated, disabled-by-default acceptance broker service core.

The provider adapter owns credentials. This service holds no Factory state or
release authority and never retries an uncertain provider outcome.
"""
from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass
from datetime import datetime
from decimal import Decimal
from pathlib import Path
from typing import Protocol

from factory_state.model import StateError
from factory_state.scope import canonical

from .acceptance_budget import DynamoDBAcceptanceBudgetStore
from .autonomy import AutonomyActivation
from .autonomy_contract import load_autonomy_operating_allowance


class AcceptanceProvider(Protocol):
    def generate(self, *, input_bytes: bytes, model_id: str,
                 maximum_cost_usd: Decimal) -> tuple[bytes, Decimal]: ...


class AcceptanceClaimStore(Protocol):
    def begin(self, *, activation_id: str, dispatch_id: str,
              event_digest: str) -> dict | None: ...

    def complete(self, *, activation_id: str, dispatch_id: str,
                 event_digest: str, response: dict) -> None: ...


@dataclass
class AcceptanceBrokerService:
    repository_root: Path
    activation: AutonomyActivation
    budget: DynamoDBAcceptanceBudgetStore
    claims: AcceptanceClaimStore
    provider: AcceptanceProvider
    clock: object
    enabled: bool = False

    def handle(self, event: dict) -> dict:
        if self.enabled is not True:
            raise StateError('acceptance broker is disabled')
        now = self.clock()
        allowance = load_autonomy_operating_allowance(Path(self.repository_root))
        if (not allowance.activation_ready or allowance.production_release_authorized or
                not isinstance(now, datetime) or now.tzinfo is None or
                not allowance.pricing_observed_at <= now < allowance.pricing_expires_at):
            raise StateError('acceptance broker activation or pricing is not ready')
        self.activation.validate(now)
        fields = {'schema_version', 'kind', 'activation_id', 'dispatch_id',
                  'source_commit', 'contract_digest', 'task_id', 'target_alias',
                  'model_id', 'maximum_cost_usd', 'input_digest', 'input_base64'}
        if (not isinstance(event, dict) or set(event) != fields or
                event['schema_version'] != '1.0' or
                event['kind'] != 'acceptance_provider_call' or
                event['activation_id'] != self.activation.activation_id or
                event['source_commit'] != self.activation.source_commit or
                event['contract_digest'] != self.activation.contract_digest or
                event['task_id'] != self.activation.task_id or
                event['task_id'] != allowance.acceptance_task_id or
                event['target_alias'] != allowance.target_alias or
                event['model_id'] != allowance.model_id or
                event['maximum_cost_usd'] != str(allowance.maximum_cost_per_call)):
            raise StateError('acceptance broker request binding differs')
        from factory_state.model import SAFE_IDENTIFIER
        if (not isinstance(event['dispatch_id'], str) or
                not SAFE_IDENTIFIER.fullmatch(event['dispatch_id']) or
                not isinstance(event['input_base64'], str) or
                len(event['input_base64']) > ((42020 + 2) // 3) * 4):
            raise StateError('acceptance broker input is invalid')
        try:
            raw = base64.b64decode(event['input_base64'], validate=True)
        except (ValueError, TypeError) as error:
            raise StateError('acceptance broker input encoding is invalid') from error
        digest = 'sha256:' + hashlib.sha256(raw).hexdigest()
        if len(raw) > 42020 or event['input_digest'] != digest:
            raise StateError('acceptance broker input digest differs')
        self.budget.assert_reserved(
            activation_id=self.activation.activation_id, dispatch_id=event['dispatch_id'],
            maximum_cost_usd=allowance.maximum_cost_per_call,
            expires_at=self.activation.expires_at)
        event_digest = 'sha256:' + hashlib.sha256(canonical(event)).hexdigest()
        prior = self.claims.begin(activation_id=self.activation.activation_id,
                                  dispatch_id=event['dispatch_id'], event_digest=event_digest)
        if prior is not None:
            return prior
        # STARTED is durable. Any failure or timeout from here is an unknown
        # external outcome and must never cause a second provider invocation.
        output, cost = self.provider.generate(input_bytes=raw, model_id=allowance.model_id,
                                              maximum_cost_usd=allowance.maximum_cost_per_call)
        if (not isinstance(output, bytes) or len(output) > 65536 or
                not isinstance(cost, Decimal) or not cost.is_finite() or
                not 0 <= cost <= allowance.maximum_cost_per_call):
            raise StateError('acceptance broker provider result exceeds bounds')
        reply = {key: event[key] for key in (
            'activation_id', 'dispatch_id', 'source_commit', 'contract_digest',
            'task_id', 'target_alias', 'model_id', 'input_digest')}
        reply.update(output_base64=base64.b64encode(output).decode(),
                     output_digest='sha256:' + hashlib.sha256(output).hexdigest(),
                     cost_usd=str(cost), provider_calls=1)
        self.claims.complete(activation_id=self.activation.activation_id,
                             dispatch_id=event['dispatch_id'], event_digest=event_digest,
                             response=reply)
        return reply
