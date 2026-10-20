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
from .credential_issuance import CredentialIssuanceLedger


class RenewableProviderCredentialSource:
    """Coalesce renewal and retain absolute expiry without persisting secrets.

    The optional issuance ledger preserves bounds and uncertain attempts across
    restarts. Production composition must supply it before wiring a live issuer.
    """

    def __init__(self, *, target: ResolvedProviderTarget,
                 issuer: Callable[[], Awaitable[ProviderCredentialLease]],
                 clock: Callable[[], datetime], enabled: bool = False,
                 minimum_remaining_seconds: int = 210,
                 maximum_lifetime_seconds: int = 3600,
                 issuance_ledger: CredentialIssuanceLedger | None = None):
        if not isinstance(target, ResolvedProviderTarget) or target.provider_family != "openai":
            raise ValueError("an exact OpenAI target is required")
        if type(enabled) is not bool or not callable(issuer) or not callable(clock):
            raise ValueError("invalid renewal configuration")
        if (type(minimum_remaining_seconds) is not int
                or type(maximum_lifetime_seconds) is not int
                or not 1 <= minimum_remaining_seconds < maximum_lifetime_seconds <= 3600):
            raise ValueError("invalid credential lifetime bounds")
        self._target = target
        if issuance_ledger is not None and (
                not isinstance(issuance_ledger, CredentialIssuanceLedger)
                or issuance_ledger.authorization.target != target):
            raise ValueError("issuance ledger target mismatch")
        self._ledger = issuance_ledger
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

    def _validate(self, lease: ProviderCredentialLease, now: datetime, *, renewal_started_at=None) -> None:
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
        if (self._ledger is not None and
                timedelta(seconds=self._ledger.authorization.minimum_interval_seconds)
                > lease.expires_at - renewal_started_at - self._minimum):
            raise ValueError("renewal interval exceeds usable credential window")

    async def issue(self, *, target: ResolvedProviderTarget) -> ProviderCredentialLease:
        if not self._enabled or target != self._target:
            raise ProviderCredentialLeaseError("credential renewal disabled or target mismatch")
        async with self._lock:
            if self._failed:
                raise ProviderCredentialLeaseError("credential renewal requires reconciliation")
            claim = None
            try:
                now = self._now()
                if self._ledger is not None:
                    self._ledger.check(now=now, target=target)
                if self._lease is not None and self._lease.expires_at - now > self._minimum:
                    return self._lease
                self._lease = None
                if self._ledger is not None:
                    claim = self._ledger.claim(now=now, target=target)
                lease = await self._issuer()
                completed_at = self._now()
                self._validate(lease, completed_at, renewal_started_at=now)
                if self._ledger is not None:
                    self._ledger.finish(claim, succeeded=True, now=completed_at)
                    claim = None
                self._lease = lease
                return lease
            except BaseException as error:
                self._lease = None
                self._failed = True
                if claim is not None:
                    try:
                        self._ledger.finish(claim, succeeded=False)
                    except Exception:
                        pass  # STARTED is already durable and blocks all future claims.
                if isinstance(error, (asyncio.CancelledError, KeyboardInterrupt, SystemExit)):
                    raise
                raise ProviderCredentialLeaseError("credential renewal failed; reconciliation required") from None
