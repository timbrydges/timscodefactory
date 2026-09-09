"""Composition helpers for the brokered, bounded CI repair runtime.

This module joins the already-separated Factory components without changing
their authority boundaries:

Factory config -> provider broker binding -> structured repair model/strategy
-> bounded repair controller -> independent runtime verification.

Every brokered repair execution also produces a validated tamper-evident trace.
Trace generation remains non-authoritative: it cannot promote a repair, mutate
Factory state, or change the controller's success decision.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from .brokered_repair_trace import (
    BrokeredRepairTraceArtifact,
    BrokeredRepairTraceStore,
    InMemoryBrokeredRepairTraceStore,
    build_brokered_repair_trace,
)
from .detector import BaseImagePolicy
from .docker_provisioner import DockerProvisioningPolicy
from .pipeline import DockerVerificationFactory
from .provider_broker import (
    BrokerCredentialSource,
    BrokerTransport,
    ProviderBrokerBinding,
    ProviderBrokerBudget,
    ProviderBrokerCallRecord,
    ProviderBrokerRepairModel,
    load_provider_broker_binding,
)
from .repair import (
    BoundedCIRepairController,
    DockerRuntimePipelineFactory,
    RepairOutcome,
    RepairPolicy,
    RepairRequest,
    RuntimePipelineFactory,
    VerifiedRepairCandidate,
)
from .structured_repair import StructuredAIRepairStrategy, StructuredRepairPolicy


@dataclass(frozen=True)
class BrokeredCIRepairRuntime:
    """One composed non-authoritative repair runtime with required telemetry.

    The controller owns candidate isolation and success decisions. The provider
    model remains non-authoritative. A completed repair is returned only after
    its metadata-only trace validates, replays, and is accepted by the trace
    sink.

    Execution is serialized per runtime instance so provider call records cannot
    interleave between concurrent repairs. Horizontal concurrency should use
    multiple runtime instances.
    """

    binding: ProviderBrokerBinding
    provider_model: ProviderBrokerRepairModel
    strategy: StructuredAIRepairStrategy
    controller: BoundedCIRepairController
    trace_store: BrokeredRepairTraceStore = field(
        default_factory=InMemoryBrokeredRepairTraceStore,
        compare=False,
        repr=False,
    )
    _repair_lock: asyncio.Lock = field(
        default_factory=asyncio.Lock,
        compare=False,
        repr=False,
    )

    @property
    def spent_usd(self):
        return self.provider_model.spent_usd

    @property
    def provider_calls(self) -> tuple[ProviderBrokerCallRecord, ...]:
        return self.provider_model.call_records

    async def repair_with_trace(
        self,
        request: RepairRequest,
    ) -> tuple[RepairOutcome, BrokeredRepairTraceArtifact]:
        """Execute one repair and return its validated telemetry artifact."""

        async with self._repair_lock:
            started_at = datetime.now(timezone.utc)
            call_offset = len(self.provider_model.call_records)
            outcome = await self.controller.repair(request)
            calls = self.provider_model.call_records[call_offset:]
            try:
                artifact = build_brokered_repair_trace(
                    request,
                    outcome,
                    calls,
                    started_at=started_at,
                )
                self.trace_store.store(artifact)
            except Exception:
                if isinstance(outcome, VerifiedRepairCandidate):
                    outcome.cleanup()
                raise
            return outcome, artifact

    async def repair(self, request: RepairRequest) -> RepairOutcome:
        outcome, _artifact = await self.repair_with_trace(request)
        return outcome


def compose_brokered_ci_repair_runtime(
    factory_repository_root: Path,
    authoritative_workspace: Path,
    runtime_factory: RuntimePipelineFactory,
    credential_source: BrokerCredentialSource,
    broker_transport: BrokerTransport,
    broker_budget: ProviderBrokerBudget,
    *,
    structured_policy: StructuredRepairPolicy | None = None,
    repair_policy: RepairPolicy | None = None,
    trace_store: BrokeredRepairTraceStore | None = None,
) -> BrokeredCIRepairRuntime:
    """Compose a brokered repair runtime around any verification runtime factory."""

    binding = load_provider_broker_binding(factory_repository_root)
    provider_model = ProviderBrokerRepairModel(
        binding,
        credential_source,
        broker_transport,
        broker_budget,
    )
    strategy = StructuredAIRepairStrategy(provider_model, structured_policy)
    controller = BoundedCIRepairController(
        authoritative_workspace,
        runtime_factory,
        strategy,
        repair_policy,
    )
    return BrokeredCIRepairRuntime(
        binding=binding,
        provider_model=provider_model,
        strategy=strategy,
        controller=controller,
        trace_store=trace_store or InMemoryBrokeredRepairTraceStore(),
    )


def build_docker_brokered_ci_repair_runtime(
    factory_repository_root: Path,
    authoritative_workspace: Path,
    image_policy: BaseImagePolicy,
    provisioning_policy: DockerProvisioningPolicy,
    credential_source: BrokerCredentialSource,
    broker_transport: BrokerTransport,
    broker_budget: ProviderBrokerBudget,
    *,
    verification_factory: DockerVerificationFactory | None = None,
    structured_policy: StructuredRepairPolicy | None = None,
    repair_policy: RepairPolicy | None = None,
    trace_store: BrokeredRepairTraceStore | None = None,
) -> BrokeredCIRepairRuntime:
    """Build the concrete Docker-backed brokered CI repair runtime."""

    runtime_factory = DockerRuntimePipelineFactory(
        image_policy=image_policy,
        provisioning_policy=provisioning_policy,
        verification_factory=verification_factory,
    )
    return compose_brokered_ci_repair_runtime(
        factory_repository_root,
        authoritative_workspace,
        runtime_factory,
        credential_source,
        broker_transport,
        broker_budget,
        structured_policy=structured_policy,
        repair_policy=repair_policy,
        trace_store=trace_store,
    )
