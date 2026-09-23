"""Fail-closed operational backend boundary for the autonomy acceptance task."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from decimal import Decimal
from pathlib import Path
from typing import Protocol

from factory_state.model import StateError

from .autonomy import AutonomyActivation
from .autonomy_contract import AutonomyOperatingAllowance, load_autonomy_operating_allowance


class AtomicAcceptanceBudgetStore(Protocol):
    def reserve(
        self,
        *,
        activation_id: str,
        dispatch_id: str,
        maximum_cost_usd: Decimal,
        maximum_provider_calls: int,
        expires_at: datetime,
    ) -> None: ...


class AcceptanceTaskExecutor(Protocol):
    def execute(
        self,
        *,
        task_id: str,
        target_alias: str,
        model_id: str,
        input_bytes: bytes,
        maximum_cost_usd: Decimal,
    ) -> bytes: ...


@dataclass
class AcceptanceOperationalBackend:
    """Role-side guard around one injected, credential-free task executor.

    The executor may call only the separately authenticated provider broker. It
    receives no provider credential and cannot change activation or budget data.
    """

    repository_root: Path
    activation: AutonomyActivation
    budget_store: AtomicAcceptanceBudgetStore
    executor: AcceptanceTaskExecutor
    enabled: bool = False

    def __post_init__(self) -> None:
        self.repository_root = Path(self.repository_root).resolve()
        if type(self.enabled) is not bool:
            raise StateError("operational backend activation must be explicit")

    def _allowance(self) -> AutonomyOperatingAllowance:
        allowance = load_autonomy_operating_allowance(self.repository_root)
        if allowance.production_release_authorized:
            raise StateError("operational backend cannot hold production release authority")
        if not allowance.activation_ready:
            raise StateError("operational backend has pending activation gates")
        if allowance.target_alias != "coding_primary_sol_live" or allowance.model_id != "gpt-5.6-sol":
            raise StateError("operational backend target differs from owner authorization")
        return allowance

    def check_activation(self, state, request, *, now: datetime) -> None:
        if not self.enabled:
            raise StateError("operational backend is disabled")
        allowance = self._allowance()
        self.activation.validate(now)
        if (
            state.factory_id != self.activation.factory_id
            or state.task_id != self.activation.task_id
            or state.task_id != allowance.acceptance_task_id
            or request.source_commit != self.activation.source_commit
            or request.contract_digest != self.activation.contract_digest
        ):
            raise StateError("operational backend binding differs from approved activation")

    def reserve(self, state, request, *, dispatch_id: str, now: datetime) -> None:
        self.check_activation(state, request, now=now)
        allowance = self._allowance()
        self.budget_store.reserve(
            activation_id=self.activation.activation_id,
            dispatch_id=dispatch_id,
            maximum_cost_usd=allowance.maximum_cost_per_call,
            maximum_provider_calls=allowance.maximum_provider_calls,
            expires_at=self.activation.expires_at,
        )

    def execute(self, state, request, *, dispatch_id: str, input_bytes: bytes) -> bytes:
        del dispatch_id
        allowance = self._allowance()
        if not self.enabled:
            raise StateError("operational backend is disabled")
        if not isinstance(input_bytes, bytes) or len(input_bytes) > allowance.maximum_request_bytes_at_cost_cap:
            raise StateError("operational backend input exceeds the approved cost bound")
        output = self.executor.execute(
            task_id=allowance.acceptance_task_id,
            target_alias=allowance.target_alias,
            model_id=allowance.model_id,
            input_bytes=input_bytes,
            maximum_cost_usd=allowance.maximum_cost_per_call,
        )
        if not isinstance(output, bytes) or len(output) > 65536:
            raise StateError("operational backend output exceeds the bounded role format")
        return output
