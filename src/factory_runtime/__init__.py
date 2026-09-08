"""Factory-owned runtime interfaces below the authoritative control plane."""

from .detector import (
    BaseImagePolicy,
    DetectionResult,
    EnvironmentDetectionError,
    detect_environment,
)
from .docker_sandbox import (
    DockerSandboxAdapter,
    DockerSandboxPolicy,
    SandboxExecutionError,
    workspace_tree_digest,
)
from .environment import (
    EnvironmentSpec,
    ProvisionInput,
    ProvisionStep,
    ProvisionerAdapter,
    ProvisioningContractError,
    ProvisioningReceipt,
    ProvisioningRequest,
    ValidatedProvisioningReceipt,
    validate_provisioning_receipt,
)
from .sandbox import (
    SandboxAdapter,
    SandboxContractError,
    SandboxReceipt,
    SandboxRequest,
    ValidatedSandboxReceipt,
    command_digest,
    validate_sandbox_receipt,
)

__all__ = [
    "BaseImagePolicy",
    "DetectionResult",
    "DockerSandboxAdapter",
    "DockerSandboxPolicy",
    "EnvironmentDetectionError",
    "EnvironmentSpec",
    "ProvisionInput",
    "ProvisionStep",
    "ProvisionerAdapter",
    "ProvisioningContractError",
    "ProvisioningReceipt",
    "ProvisioningRequest",
    "SandboxAdapter",
    "SandboxContractError",
    "SandboxExecutionError",
    "SandboxReceipt",
    "SandboxRequest",
    "ValidatedProvisioningReceipt",
    "ValidatedSandboxReceipt",
    "command_digest",
    "detect_environment",
    "validate_provisioning_receipt",
    "validate_sandbox_receipt",
    "workspace_tree_digest",
]
