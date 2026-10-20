"""In-memory renewal policy; no network transport or credential store access.

The injected issuer must return provider-enforced expiry, not a locally extended
static-key lifetime. Activation and identity-provider provisioning are external
approval gates. A failed/uncertain issuance permanently stops this instance.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
from typing import Awaitable, Callable

from .openai_provider import ProviderCredentialLease
from .provider_broker_service import ResolvedProviderTarget
from .provider_credentials import ProviderCredentialLeaseError


class RenewableProviderCredentialSource:
    """Coalesce renewal and retain absolute expiry without persisting secrets.

    This is a process-local policy, not a durable exchange authorization ledger.
    Production composition must provide that ledger before wiring a live issuer.
    """

    def __init__(self, *, target: ResolvedProviderTarget,
                 issuer: Callable[[], Awaitable[ProviderCredentialLease]],
                 clock: Callable[[], datetime], enabled: bool = False,
                 minimum_remaining_seconds: int = 210,
                 maximum_lifetime_seconds: int = 3600):
        if not isinstance(target, ResolvedProviderTarget) or target.provider_family != "openai":
            raise ValueError("an exact OpenAI target is required")
        if type(enabled) is not bool or not callable(issuer) or not callable(clock):
            raise ValueError("invalid renewal configuration")
        if (type(minimum_remaining_seconds) is not int
                or type(maximum_lifetime_seconds) is not int
                or not 1 <= minimum_remaining_seconds < maximum_lifetime_seconds <= 3600):
            raise ValueError("invalid credential lifetime bounds")
        self._target = target
        self._issuer = issuer
        self._clock = clock
        self._enabled = enabled
        self._minimum = timedelta(seconds=minimum_remaining_seconds)
        self._maximum = timedelta(seconds=maximum_lifetime_seconds)
        self._lock = asyncio.Lock()
        self._lease: ProviderCredentialLease | None = None
        self._failed = False
        self._last_now: datetime | None = None

    def _now(self) -> datetime:
        now = self._clock()
        if not isinstance(now, datetime) or now.tzinfo is None or now.utcoffset() is None:
            raise ValueError("aware clock required")
        now = now.astimezone(timezone.utc)
        if self._last_now is not None and now < self._last_now:
            raise ValueError("clock moved backwards")
        self._last_now = now
        return now

    def _validate(self, lease: ProviderCredentialLease, now: datetime) -> None:
        if not isinstance(lease, ProviderCredentialLease):
            raise ValueError("invalid issuer result")
        if lease.provider_family != "openai" or lease.audience != "api.openai.com":
            raise ValueError("invalid credential audience")
        if (not isinstance(lease.token, str) or not 16 <= len(lease.token) <= 32768
                or any(ord(c) < 33 or ord(c) > 126 for c in lease.token)):
            raise ValueError("invalid credential token")
        for value in (lease.issued_at, lease.expires_at):
            if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
                raise ValueError("invalid credential timestamps")
        if (lease.issued_at > now or lease.expires_at - lease.issued_at > self._maximum
                or lease.expires_at - now <= self._minimum):
            raise ValueError("credential lifetime unavailable")

    async def issue(self, *, target: ResolvedProviderTarget) -> ProviderCredentialLease:
        if not self._enabled or target != self._target:
            raise ProviderCredentialLeaseError("credential renewal disabled or target mismatch")
        async with self._lock:
            if self._failed:
                raise ProviderCredentialLeaseError("credential renewal requires reconciliation")
            try:
                now = self._now()
                if self._lease is not None and self._lease.expires_at - now > self._minimum:
                    return self._lease
                self._lease = None
                lease = await self._issuer()
                self._validate(lease, self._now())
                self._lease = lease
                return lease
            except BaseException as error:
                self._lease = None
                self._failed = True
                if isinstance(error, (asyncio.CancelledError, KeyboardInterrupt, SystemExit)):
                    raise
                raise ProviderCredentialLeaseError("credential renewal failed; reconciliation required") from None
