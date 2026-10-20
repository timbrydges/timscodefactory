"""Local issuance accounting. Contains metadata only; never tokens or transport.

Trusted operator code authenticates the approval and constructs this binding.
Deleting or replacing the ledger is not an approved recovery procedure.
"""
from contextlib import contextmanager
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import json
from pathlib import Path
import re
import sqlite3
import uuid

from .provider_broker_service import ResolvedProviderTarget
from .provider_credentials import ProviderCredentialLeaseError


def _time(value):
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("aware issuance time required")
    return value.astimezone(timezone.utc).timestamp()


@dataclass(frozen=True)
class IssuanceAuthorization:
    approval_digest: str
    identity_provider_id: str
    service_account_id: str
    target: ResolvedProviderTarget
    starts_at: datetime
    expires_at: datetime
    maximum_exchanges: int
    scopes: tuple[str, ...]
    minimum_interval_seconds: int = 210

    def canonical(self):
        if not isinstance(self.approval_digest, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", self.approval_digest):
            raise ValueError("exact approval digest required")
        for value in (self.identity_provider_id, self.service_account_id):
            if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", value):
                raise ValueError("bounded identity binding required")
        if not isinstance(self.target, ResolvedProviderTarget) or self.target.provider_family != "openai":
            raise ValueError("exact OpenAI target required")
        if (type(self.scopes) is not tuple or not 1 <= len(self.scopes) <= 32
                or any(not isinstance(scope, str) or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,128}", scope)
                       for scope in self.scopes)
                or tuple(sorted(set(self.scopes))) != self.scopes):
            raise ValueError("exact sorted unique scopes required")
        start, end = _time(self.starts_at), _time(self.expires_at)
        if not 0 < end - start <= 86400:
            raise ValueError("issuance window must be at most 24 hours")
        if type(self.maximum_exchanges) is not int or not 1 <= self.maximum_exchanges <= 1000:
            raise ValueError("bounded exchange count required")
        if type(self.minimum_interval_seconds) is not int or not 1 <= self.minimum_interval_seconds <= 3600:
            raise ValueError("bounded renewal interval required")
        data = asdict(self)
        data.update(starts_at=start, expires_at=end)
        return json.dumps(data, sort_keys=True, separators=(",", ":"))


class CredentialIssuanceLedger:
    def __init__(self, path, authorization, *, operator_authorized=False):
        if operator_authorized is not True:
            raise ProviderCredentialLeaseError("issuance admission not authorized")
        if not isinstance(authorization, IssuanceAuthorization):
            raise ValueError("issuance authorization required")
        self._binding = authorization.canonical()
        self.authorization = authorization
        self.path = Path(path)
        if self.path.is_symlink() or self.path.parent.is_symlink() or not self.path.parent.is_dir():
            raise ValueError("regular issuance ledger path required")
        with self._db() as db:
            db.execute("CREATE TABLE IF NOT EXISTS issuance_policy (id INTEGER PRIMARY KEY CHECK(id=1), binding TEXT NOT NULL, paused INTEGER NOT NULL, last_time REAL)")
            db.execute("CREATE TABLE IF NOT EXISTS issuance_attempts (claim TEXT PRIMARY KEY, started REAL NOT NULL, status TEXT NOT NULL)")
            db.execute("INSERT OR IGNORE INTO issuance_policy VALUES (1,?,1,NULL)", (self._binding,))
            if db.execute("SELECT binding FROM issuance_policy WHERE id=1").fetchone()[0] != self._binding:
                raise ProviderCredentialLeaseError("issuance authorization cannot change")

    @contextmanager
    def _db(self):
        db = sqlite3.connect(self.path, timeout=5)
        try:
            with db:
                yield db
        finally:
            db.close()

    def pause(self, paused=True):
        if type(paused) is not bool:
            raise ValueError("boolean pause required")
        with self._db() as db:
            db.execute("UPDATE issuance_policy SET paused=? WHERE id=1", (int(paused),))

    def _check(self, db, now, target):
        stamp = _time(now)
        binding, paused, last = db.execute("SELECT binding,paused,last_time FROM issuance_policy WHERE id=1").fetchone()
        if (binding != self._binding or paused or target != self.authorization.target
                or not _time(self.authorization.starts_at) <= stamp < _time(self.authorization.expires_at)
                or (last is not None and stamp < last)):
            raise ProviderCredentialLeaseError("issuance policy unavailable")
        if db.execute("SELECT 1 FROM issuance_attempts WHERE status != 'SUCCEEDED' LIMIT 1").fetchone():
            raise ProviderCredentialLeaseError("issuance requires reconciliation")
        db.execute("UPDATE issuance_policy SET last_time=? WHERE id=1", (stamp,))
        return stamp

    def check(self, *, now, target):
        with self._db() as db:
            db.execute("BEGIN IMMEDIATE")
            self._check(db, now, target)

    def claim(self, *, now, target):
        with self._db() as db:
            db.execute("BEGIN IMMEDIATE")
            stamp = self._check(db, now, target)
            count, last = db.execute("SELECT COUNT(*),MAX(started) FROM issuance_attempts").fetchone()
            if (count >= self.authorization.maximum_exchanges or
                    (last is not None and stamp - last < self.authorization.minimum_interval_seconds)):
                raise ProviderCredentialLeaseError("issuance allowance unavailable")
            claim = uuid.uuid4().hex
            db.execute("INSERT INTO issuance_attempts VALUES (?,?,'STARTED')", (claim, stamp))
            return claim

    def finish(self, claim, *, succeeded, now=None):
        if type(succeeded) is not bool:
            raise ValueError("explicit issuance result required")
        with self._db() as db:
            db.execute("BEGIN IMMEDIATE")
            if succeeded:
                stamp = _time(now)
                binding, paused, last = db.execute("SELECT binding,paused,last_time FROM issuance_policy WHERE id=1").fetchone()
                if (binding != self._binding or paused or last is None or stamp < last
                        or stamp >= _time(self.authorization.expires_at)):
                    raise ProviderCredentialLeaseError("issuance completion outside authorization")
                db.execute("UPDATE issuance_policy SET last_time=? WHERE id=1", (stamp,))
            result = db.execute("UPDATE issuance_attempts SET status=? WHERE claim=? AND status='STARTED'",
                                ("SUCCEEDED" if succeeded else "UNCERTAIN", claim))
            if result.rowcount != 1:
                raise ProviderCredentialLeaseError("issuance claim is not active")
