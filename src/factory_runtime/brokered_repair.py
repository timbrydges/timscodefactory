"""Composition helpers for the brokered, bounded CI repair runtime.

This module joins the already-separated Factory components without changing
their authority boundaries:

Factory config -> provider broker binding -> structured repair model/strategy
-> bounded repair controller -> independent runtime verification.

The Factory configuration repository and the target code workspace are separate
inputs. The provider model remains non-authoritative, and successful repair still
requires the controller's exact-command sandbox verification.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

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
)
from .structured_repair import StructuredAIRepairStrategy, StructuredRepairPolicy


@dataclass(frozen=True)
class BrokeredCIRepairRuntime:
    """One composed non-authoritative repair runtime.

    The controller owns candidate isolation and success decisions. The provider
    model is exposed only for cost/audit telemetry; it cannot publish or promote
    a repair.
    """

    binding: ProviderBrokerBinding
    provider_model: ProviderBrokerRepairModel
    strategy: StructuredAIRepairStrategy
    controller: BoundedCIRepairController

    @property
    def spent_usd(self):
        return self.provider_model.spent_usd

    @property
    def provider_calls(self) -> tuple[ProviderBrokerCallRecord, ...]:
        return self.provider_model.call_records

    async def repair(self, request: RepairRequest) -> RepairOutcome:
        return await self.controller.repair(request)


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
    )
