"""Credential lease helpers for live provider invocation.

The provider broker may hold a longer-lived vendor secret in its deployment
secret store, but the OpenAI adapter receives only a short-lived in-memory lease.
This module never serializes, logs, persists, or returns the backing secret
outside ProviderCredentialLease.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Mapping, Protocol

from .openai_provider import ProviderCredentialLease
from .provider_broker_service import ProviderBrokerInvocationError, ResolvedProviderTarget


class ProviderCredentialLeaseError(ProviderBrokerInvocationError):
    """A provider credential lease could not be issued safely."""


_SECRET_ARN = re.compile(
    r"^arn:(aws|aws-us-gov|aws-cn):secretsmanager:ca-central-1:[0-9]{12}:"
    r"secret:tims-software-factory/provider/openai/acceptance-[A-Za-z0-9]{6}$"
)
_SECRET_NAME = "tims-software-factory/provider/openai/acceptance"


class SecretsManagerClient(Protocol):
    def get_secret_value(self, **kwargs: Any) -> dict[str, Any]:
        ...


def secrets_manager_client(session):
    """Create the exact-region, no-retry Secrets Manager client."""
    from botocore.config import Config

    return session.client(
        "secretsmanager",
        region_name="ca-central-1",
        endpoint_url="https://secretsmanager.ca-central-1.amazonaws.com",
        config=Config(
            connect_timeout=3,
            read_timeout=5,
            retries={"max_attempts": 0, "mode": "standard"},
        ),
    )


@dataclass(frozen=True)
class EnvironmentProviderCredentialLeaseSource:
    """Lease a broker-injected OpenAI secret for a bounded in-memory lifetime.

    The environment is treated as the deployment secret injection boundary. The
    source does not create a new vendor credential; it narrows exposure of the
    broker-held secret to one short-lived ProviderCredentialLease object.
    """

    environment_variable: str = "FACTORY_OPENAI_API_KEY"
    lease_ttl_seconds: int = 300
    provider_family: str = "openai"
    audience: str = "api.openai.com"
    environment: Mapping[str, str] | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.environment_variable, str) or not self.environment_variable:
            raise ValueError("environment_variable must be a nonempty string")
        if any(not (ch.isupper() or ch.isdigit() or ch == "_") for ch in self.environment_variable):
            raise ValueError("environment_variable must use uppercase environment-key syntax")
        if isinstance(self.lease_ttl_seconds, bool) or not isinstance(self.lease_ttl_seconds, int):
            raise ValueError("lease_ttl_seconds must be an integer")
        if not 30 <= self.lease_ttl_seconds <= 900:
            raise ValueError("lease_ttl_seconds must be between 30 and 900")
        if self.provider_family != "openai" or self.audience != "api.openai.com":
            raise ValueError("credential lease source is bound to OpenAI api.openai.com")

    async def issue(self, *, target: ResolvedProviderTarget) -> ProviderCredentialLease:
        if not isinstance(target, ResolvedProviderTarget):
            raise ProviderCredentialLeaseError("resolved provider target is required")
        if target.provider_family != self.provider_family:
            raise ProviderCredentialLeaseError("provider target family does not match credential source")
        env = os.environ if self.environment is None else self.environment
        token = env.get(self.environment_variable)
        if not isinstance(token, str) or len(token) < 16:
            raise ProviderCredentialLeaseError("provider credential is unavailable")
        if any(ord(ch) < 33 or ord(ch) > 126 for ch in token):
            raise ProviderCredentialLeaseError("provider credential contains invalid characters")
        now = datetime.now(timezone.utc)
        return ProviderCredentialLease(
            token=token,
            provider_family=self.provider_family,
            audience=self.audience,
            issued_at=now,
            expires_at=now + timedelta(seconds=self.lease_ttl_seconds),
        )


@dataclass(frozen=True)
class SecretsManagerProviderCredentialLeaseSource:
    """Read one exact AWSCURRENT secret into one short-lived in-memory lease."""

    client: SecretsManagerClient
    secret_arn: str
    lease_ttl_seconds: int = 300
    provider_family: str = "openai"
    audience: str = "api.openai.com"

    def __post_init__(self) -> None:
        if not isinstance(self.secret_arn, str) or not _SECRET_ARN.fullmatch(self.secret_arn):
            raise ValueError("secret_arn must bind the exact Factory acceptance secret")
        if isinstance(self.lease_ttl_seconds, bool) or not isinstance(
                self.lease_ttl_seconds, int):
            raise ValueError("lease_ttl_seconds must be an integer")
        if not 30 <= self.lease_ttl_seconds <= 300:
            raise ValueError("Secrets Manager lease TTL must be between 30 and 300 seconds")
        if self.provider_family != "openai" or self.audience != "api.openai.com":
            raise ValueError("credential lease source is bound to OpenAI api.openai.com")

    async def issue(self, *, target: ResolvedProviderTarget) -> ProviderCredentialLease:
        if not isinstance(target, ResolvedProviderTarget):
            raise ProviderCredentialLeaseError("resolved provider target is required")
        if target.provider_family != self.provider_family:
            raise ProviderCredentialLeaseError(
                "provider target family does not match credential source")
        try:
            result = self.client.get_secret_value(
                SecretId=self.secret_arn,
                VersionStage="AWSCURRENT",
            )
        except Exception as error:
            raise ProviderCredentialLeaseError(
                "provider credential is unavailable") from error
        if not isinstance(result, dict):
            raise ProviderCredentialLeaseError("provider secret response is invalid")
        if result.get("ARN") != self.secret_arn or result.get("Name") != _SECRET_NAME:
            raise ProviderCredentialLeaseError("provider secret identity mismatch")
        stages = result.get("VersionStages")
        if not isinstance(stages, list) or "AWSCURRENT" not in stages:
            raise ProviderCredentialLeaseError("provider secret is not AWSCURRENT")
        if "SecretBinary" in result:
            raise ProviderCredentialLeaseError("binary provider secrets are prohibited")
        token = result.get("SecretString")
        if not isinstance(token, str) or len(token) < 16:
            raise ProviderCredentialLeaseError("provider credential is unavailable")
        if any(ord(ch) < 33 or ord(ch) > 126 for ch in token):
            raise ProviderCredentialLeaseError(
                "provider credential contains invalid characters")
        now = datetime.now(timezone.utc)
        return ProviderCredentialLease(
            token=token,
            provider_family=self.provider_family,
            audience=self.audience,
            issued_at=now,
            expires_at=now + timedelta(seconds=self.lease_ttl_seconds),
        )
