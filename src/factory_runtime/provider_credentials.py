"""Credential lease helpers for live provider invocation.

The provider broker may hold a longer-lived vendor secret in its deployment
secret store, but the OpenAI adapter receives only a short-lived in-memory lease.
This module never serializes, logs, persists, or returns the backing secret
outside ProviderCredentialLease.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Mapping

from .openai_provider import ProviderCredentialLease
from .provider_broker_service import ProviderBrokerInvocationError, ResolvedProviderTarget


class ProviderCredentialLeaseError(ProviderBrokerInvocationError):
    """A provider credential lease could not be issued safely."""


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
