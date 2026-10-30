"""Validate injected JWT exchange responses; no HTTP or identity-source access.

The future transport must authenticate the provider endpoint, bind the exact
mapping, and obtain subject expiry from its trusted identity source. Parsing
does not verify a JWT signature or establish trust in arbitrary response bytes.
"""
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import json
import hashlib
import re

from .identity_diagnostics import IdentityFailure
from .credential_issuance import CredentialIssuanceLedger, IssuanceAuthorization
from .openai_provider import ProviderCredentialLease
from .provider_credentials import ProviderCredentialLeaseError
from .renewable_credentials import RenewableProviderCredentialSource


@dataclass(frozen=True, repr=False)
class ExchangeResponse:
    body: bytes
    subject_expires_at: datetime


@dataclass(frozen=True, repr=False)
class RenewableCredentialBinding:
    """Trusted operator binding; never deserialize a transport from task data."""
    ledger: CredentialIssuanceLedger
    exchange: object

    def __post_init__(self):
        if type(self.ledger) is not CredentialIssuanceLedger or not callable(self.exchange):
            raise ValueError("exact ledger and trusted exchange callback required")

    @property
    def source_pin(self):
        document = dict(schema=1, authorization=json.loads(self.ledger.authorization.canonical()),
                        ledger_path=str(self.ledger.path),
                        minimum_remaining_seconds=210, maximum_lifetime_seconds=900)
        encoded = json.dumps(document, sort_keys=True, separators=(",", ":")).encode()
        return "wif:sha256:" + hashlib.sha256(encoded).hexdigest()

    def compose(self, *, clock):
        return compose_exchange_credential_source(ledger=self.ledger, exchange=self.exchange,
            clock=clock, enabled=True, minimum_remaining_seconds=210, maximum_lifetime_seconds=900)


def _aware(value):
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("aware exchange timestamp required")
    return value.astimezone(timezone.utc)


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate exchange field")
        result[key] = value
    return result


def parse_exchange_response(response, *, requested_at, received_at, expected_scopes):
    """Require exact scoped access and retain the provider's absolute expiry."""
    # Only fixed labels may escape; never derive diagnostics from response data.
    reason = 'response_boundary'
    try:
        if not isinstance(response, ExchangeResponse) or type(response.body) is not bytes:
            raise ValueError("bounded response required")
        if not 1 <= len(response.body) <= 65536:
            raise ValueError("bounded response required")
        reason = 'response_clock'
        start, end = _aware(requested_at), _aware(received_at)
        subject_end = _aware(response.subject_expires_at)
        if end < start:
            raise ValueError("exchange clock reversed")
        reason = 'expected_scopes'
        if (type(expected_scopes) is not tuple or not 1 <= len(expected_scopes) <= 32
                or any(not isinstance(scope, str) or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,128}", scope)
                       for scope in expected_scopes)
                or tuple(sorted(set(expected_scopes))) != expected_scopes):
            raise ValueError("exact scopes required")
        reason = 'response_json'
        data = json.loads(response.body.decode("utf-8"), object_pairs_hook=_unique)
        reason = 'response_fields'
        fields = {"access_token", "issued_token_type", "token_type", "expires_in", "expires_at", "scope"}
        if type(data) is not dict or set(data) != fields:
            raise ValueError("unsupported exchange response")
        reason = 'token_type'
        if (data["token_type"] != "Bearer" or
                data["issued_token_type"] != "urn:ietf:params:oauth:token-type:access_token"):
            raise ValueError("unsupported exchange token type")
        reason = 'token_encoding'
        token = data["access_token"]
        if (not isinstance(token, str) or not 16 <= len(token) <= 32768
                or any(ord(c) < 33 or ord(c) > 126 for c in token)):
            raise ValueError("invalid exchange token")
        reason = 'scope_format'
        scopes = data["scope"]
        if not isinstance(scopes, str) or len(scopes) > 4127:
            raise ValueError("invalid exchange scope")
        reason = 'scope_mismatch'
        returned_scopes = tuple(sorted(scopes.split(" ")))
        if returned_scopes != expected_scopes:
            # Fixed diagnostics only: never export arbitrary scope names.
            if returned_scopes == tuple(sorted((*expected_scopes, 'api.model.read'))):
                reason = 'scope_read_extra'
            elif set(expected_scopes) < set(returned_scopes):
                reason = 'scope_extra'
            elif not scopes or set(returned_scopes) < set(expected_scopes):
                reason = 'scope_missing'
            raise ValueError("exchange scope mismatch")
        reason = 'lifetime_format'
        ttl, expiry = data["expires_in"], data["expires_at"]
        if type(ttl) is not int or not 1 <= ttl <= 3600 or type(expiry) is not int:
            raise ValueError("invalid exchange lifetime")
        expires_at = datetime.fromtimestamp(expiry, timezone.utc)
        issued_at = expires_at - timedelta(seconds=ttl)
        # Provider times are whole seconds; allow only timestamp rounding.
        reason = 'issuance_clock'
        if issued_at < start - timedelta(seconds=1) or issued_at > end:
            raise ValueError("exchange lifetime mismatch")
        reason = 'expired'
        if expires_at <= end:
            raise ValueError("exchange lifetime mismatch")
        reason = 'subject_expiry'
        if expires_at > subject_end:
            raise ValueError("exchange lifetime mismatch")
        reason = 'validation'
        return ProviderCredentialLease(token, "openai", "api.openai.com", issued_at, expires_at)
    except Exception:
        raise IdentityFailure('exchange_response', reason) from None


def compose_exchange_credential_source(*, ledger, exchange, clock, enabled=False,
                                       minimum_remaining_seconds=210,
                                       maximum_lifetime_seconds=900):
    """Compose only injected transport; callers must not infer live authority.

    exchange(authorization) is one no-retry operation returning ExchangeResponse.
    It is invoked only after a durable claim, and never when disabled. Its real
    implementation and identity-provider provisioning remain separate gates.
    """
    if not isinstance(ledger, CredentialIssuanceLedger) or not callable(exchange) or not callable(clock):
        raise ValueError("exact ledger and injected exchange required")
    authorization: IssuanceAuthorization = ledger.authorization

    async def issuer():
        start = _aware(clock())
        if not _aware(authorization.starts_at) <= start < _aware(authorization.expires_at):
            raise ProviderCredentialLeaseError("exchange authorization expired")
        response = await exchange(authorization)
        return parse_exchange_response(response, requested_at=start, received_at=clock(),
                                       expected_scopes=authorization.scopes)

    return RenewableProviderCredentialSource(
        target=authorization.target, issuer=issuer, clock=clock, enabled=enabled,
        issuance_ledger=ledger, minimum_remaining_seconds=minimum_remaining_seconds,
        maximum_lifetime_seconds=maximum_lifetime_seconds)
