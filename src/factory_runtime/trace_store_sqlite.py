"""Durable SQLite storage for brokered repair traces and exact fingerprints.

The store persists only the Factory's already-validated metadata-only JSONL trace
plus bounded summary/fingerprint columns. It never stores source text, prompts,
logs, credentials, patches, or provider response bodies.
"""

from __future__ import annotations

import os
import re
import sqlite3
from dataclasses import dataclass
from decimal import Decimal
from pathlib import Path

from .brokered_repair_trace import (
    BrokeredRepairTraceArtifact,
    BrokeredRepairTraceError,
    FailureFingerprint,
)
from .telemetry import parse_runtime_trace_jsonl, replay_runtime_trace


_SCHEMA_VERSION = "1"
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")


class SQLiteTraceStoreError(BrokeredRepairTraceError):
    """Persistent trace store failure."""


@dataclass(frozen=True)
class FailureFingerprintHistory:
    fingerprint_digest: str
    seen_count: int
    successful_count: int
    escalated_count: int
    lowest_success_cost_usd: Decimal | None
    latest_trace_id: str


class SQLiteBrokeredRepairTraceStore:
    """Transactional restart-safe trace/fingerprint store.

    The caller chooses the database path, which should live on an appropriate
    persistent volume in deployment. This class does not place runtime data in
    the Git repository automatically.
    """

    def __init__(self, path: Path, *, max_records: int = 10_000) -> None:
        self.path = Path(path)
        if isinstance(max_records, bool) or not isinstance(max_records, int) or not (1 <= max_records <= 1_000_000):
            raise ValueError("max_records must be between 1 and 1000000")
        self.max_records = max_records
        if self.path.exists() and self.path.is_symlink():
            raise SQLiteTraceStoreError("trace database path may not be a symlink")
        parent = self.path.parent
        if not parent.exists() or not parent.is_dir() or parent.is_symlink():
            raise SQLiteTraceStoreError("trace database parent must be an existing non-symlink directory")
        if self.path.exists() and not self.path.is_file():
            raise SQLiteTraceStoreError("trace database path must be a regular file")
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        try:
            connection = sqlite3.connect(self.path, timeout=5.0)
        except sqlite3.Error as exc:
            raise SQLiteTraceStoreError("cannot open trace database") from exc
        connection.row_factory = sqlite3.Row
        try:
            connection.execute("PRAGMA foreign_keys=ON")
            connection.execute("PRAGMA busy_timeout=5000")
            connection.execute("PRAGMA journal_mode=WAL")
            connection.execute("PRAGMA synchronous=FULL")
        except sqlite3.Error:
            connection.close()
            raise
        return connection

    def _initialize(self) -> None:
        try:
            with self._connect() as connection:
                connection.executescript(
                    """
                    CREATE TABLE IF NOT EXISTS metadata (
                        key TEXT PRIMARY KEY,
                        value TEXT NOT NULL
                    );
                    CREATE TABLE IF NOT EXISTS repair_traces (
                        trace_id TEXT PRIMARY KEY,
                        repair_id TEXT NOT NULL,
                        fingerprint_version TEXT NOT NULL,
                        fingerprint_digest TEXT NOT NULL,
                        command_digest TEXT NOT NULL,
                        environment_digest TEXT,
                        stdout_digest TEXT,
                        stderr_digest TEXT,
                        exit_code INTEGER,
                        timed_out INTEGER,
                        terminal_status TEXT NOT NULL,
                        terminal_reason TEXT,
                        event_count INTEGER NOT NULL,
                        final_event_digest TEXT NOT NULL,
                        provider_cost_usd TEXT NOT NULL,
                        jsonl BLOB NOT NULL
                    );
                    CREATE INDEX IF NOT EXISTS idx_repair_traces_fingerprint
                    ON repair_traces(fingerprint_digest, trace_id);
                    """
                )
                existing = connection.execute(
                    "SELECT value FROM metadata WHERE key='schema_version'"
                ).fetchone()
                if existing is None:
                    connection.execute(
                        "INSERT INTO metadata(key, value) VALUES('schema_version', ?)",
                        (_SCHEMA_VERSION,),
                    )
                elif existing["value"] != _SCHEMA_VERSION:
                    raise SQLiteTraceStoreError("trace database schema version is unsupported")
        except sqlite3.Error as exc:
            raise SQLiteTraceStoreError("cannot initialize trace database") from exc
        try:
            os.chmod(self.path, 0o600)
        except OSError as exc:
            raise SQLiteTraceStoreError("cannot secure trace database permissions") from exc

    @staticmethod
    def _validate_artifact(artifact: BrokeredRepairTraceArtifact) -> None:
        if not isinstance(artifact, BrokeredRepairTraceArtifact):
            raise SQLiteTraceStoreError("trace store requires BrokeredRepairTraceArtifact")
        parsed = parse_runtime_trace_jsonl(artifact.jsonl)
        if parsed != artifact.events:
            raise SQLiteTraceStoreError("trace artifact JSONL does not match in-memory events")
        replay = replay_runtime_trace(parsed)
        if replay != artifact.replay:
            raise SQLiteTraceStoreError("trace artifact replay summary does not match JSONL")
        fingerprint = artifact.failure_fingerprint
        first_attributes = artifact.events[0].attributes
        if (
            first_attributes.get("failure_fingerprint_digest") != fingerprint.digest
            or first_attributes.get("failure_fingerprint_version") != fingerprint.version
            or first_attributes.get("failure_command_digest") != fingerprint.command_digest
        ):
            raise SQLiteTraceStoreError("trace-bound fingerprint metadata disagrees with artifact")
        for value in (
            fingerprint.digest,
            fingerprint.command_digest,
            fingerprint.environment_digest,
            fingerprint.stdout_digest,
            fingerprint.stderr_digest,
            replay.final_event_digest,
        ):
            if value is not None and not _DIGEST.fullmatch(value):
                raise SQLiteTraceStoreError("trace artifact contains invalid digest")

    @staticmethod
    def _timed_out_db(value: bool | None) -> int | None:
        if value is None:
            return None
        return 1 if value else 0

    def store(self, artifact: BrokeredRepairTraceArtifact) -> None:
        self._validate_artifact(artifact)
        fp = artifact.failure_fingerprint
        replay = artifact.replay
        row = (
            artifact.trace_id,
            artifact.repair_id,
            fp.version,
            fp.digest,
            fp.command_digest,
            fp.environment_digest,
            fp.stdout_digest,
            fp.stderr_digest,
            fp.exit_code,
            self._timed_out_db(fp.timed_out),
            replay.terminal_status,
            replay.terminal_reason,
            replay.event_count,
            replay.final_event_digest,
            format(replay.total_provider_cost_usd, "f"),
            artifact.jsonl,
        )
        try:
            with self._connect() as connection:
                connection.execute("BEGIN IMMEDIATE")
                existing = connection.execute(
                    "SELECT repair_id, fingerprint_digest, final_event_digest, jsonl "
                    "FROM repair_traces WHERE trace_id=?",
                    (artifact.trace_id,),
                ).fetchone()
                if existing is not None:
                    if (
                        existing["repair_id"] == artifact.repair_id
                        and existing["fingerprint_digest"] == fp.digest
                        and existing["final_event_digest"] == replay.final_event_digest
                        and bytes(existing["jsonl"]) == artifact.jsonl
                    ):
                        return
                    raise SQLiteTraceStoreError("trace_id collision with different persisted artifact")
                count = connection.execute("SELECT COUNT(*) AS n FROM repair_traces").fetchone()["n"]
                if count >= self.max_records:
                    raise SQLiteTraceStoreError("trace database capacity exhausted; explicit retention action required")
                connection.execute(
                    """
                    INSERT INTO repair_traces(
                        trace_id, repair_id, fingerprint_version, fingerprint_digest,
                        command_digest, environment_digest, stdout_digest, stderr_digest,
                        exit_code, timed_out, terminal_status, terminal_reason, event_count,
                        final_event_digest, provider_cost_usd, jsonl
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    row,
                )
        except SQLiteTraceStoreError:
            raise
        except sqlite3.Error as exc:
            raise SQLiteTraceStoreError("cannot persist runtime trace") from exc

    @staticmethod
    def _artifact_from_row(row: sqlite3.Row) -> BrokeredRepairTraceArtifact:
        raw = bytes(row["jsonl"])
        events = parse_runtime_trace_jsonl(raw)
        replay = replay_runtime_trace(events)
        if (
            replay.terminal_status != row["terminal_status"]
            or replay.terminal_reason != row["terminal_reason"]
            or replay.event_count != row["event_count"]
            or replay.final_event_digest != row["final_event_digest"]
            or format(replay.total_provider_cost_usd, "f") != row["provider_cost_usd"]
        ):
            raise SQLiteTraceStoreError("persisted trace summary disagrees with validated JSONL")
        timed_out_raw = row["timed_out"]
        if timed_out_raw not in (None, 0, 1):
            raise SQLiteTraceStoreError("persisted fingerprint timeout flag is invalid")
        fingerprint = FailureFingerprint(
            version=row["fingerprint_version"],
            digest=row["fingerprint_digest"],
            command_digest=row["command_digest"],
            environment_digest=row["environment_digest"],
            stdout_digest=row["stdout_digest"],
            stderr_digest=row["stderr_digest"],
            exit_code=row["exit_code"],
            timed_out=None if timed_out_raw is None else bool(timed_out_raw),
        )
        for value in (
            fingerprint.digest,
            fingerprint.command_digest,
            fingerprint.environment_digest,
            fingerprint.stdout_digest,
            fingerprint.stderr_digest,
        ):
            if value is not None and not _DIGEST.fullmatch(value):
                raise SQLiteTraceStoreError("persisted fingerprint contains invalid digest")
        return BrokeredRepairTraceArtifact(
            repair_id=row["repair_id"],
            trace_id=row["trace_id"],
            failure_fingerprint=fingerprint,
            events=events,
            jsonl=raw,
            replay=replay,
        )

    def get(self, trace_id: str) -> BrokeredRepairTraceArtifact | None:
        try:
            with self._connect() as connection:
                row = connection.execute(
                    "SELECT * FROM repair_traces WHERE trace_id=?",
                    (trace_id,),
                ).fetchone()
        except sqlite3.Error as exc:
            raise SQLiteTraceStoreError("cannot read runtime trace") from exc
        return None if row is None else self._artifact_from_row(row)

    def find_by_fingerprint(
        self,
        fingerprint_digest: str,
        *,
        limit: int = 20,
    ) -> tuple[BrokeredRepairTraceArtifact, ...]:
        if not isinstance(fingerprint_digest, str) or not _DIGEST.fullmatch(fingerprint_digest):
            raise SQLiteTraceStoreError("fingerprint digest is invalid")
        if isinstance(limit, bool) or not isinstance(limit, int) or not (1 <= limit <= 100):
            raise SQLiteTraceStoreError("fingerprint lookup limit must be between 1 and 100")
        try:
            with self._connect() as connection:
                rows = connection.execute(
                    "SELECT * FROM repair_traces WHERE fingerprint_digest=? ORDER BY rowid DESC LIMIT ?",
                    (fingerprint_digest, limit),
                ).fetchall()
        except sqlite3.Error as exc:
            raise SQLiteTraceStoreError("cannot query failure fingerprint history") from exc
        return tuple(self._artifact_from_row(row) for row in rows)

    def summarize_fingerprint(self, fingerprint_digest: str) -> FailureFingerprintHistory | None:
        if not isinstance(fingerprint_digest, str) or not _DIGEST.fullmatch(fingerprint_digest):
            raise SQLiteTraceStoreError("fingerprint digest is invalid")
        try:
            with self._connect() as connection:
                rows = connection.execute(
                    "SELECT trace_id, terminal_status, provider_cost_usd "
                    "FROM repair_traces WHERE fingerprint_digest=? ORDER BY rowid DESC",
                    (fingerprint_digest,),
                ).fetchall()
        except sqlite3.Error as exc:
            raise SQLiteTraceStoreError("cannot summarize failure fingerprint history") from exc
        if not rows:
            return None
        successful_costs: list[Decimal] = []
        successful_count = 0
        escalated_count = 0
        for row in rows:
            status = row["terminal_status"]
            if status == "SUCCEEDED":
                successful_count += 1
                try:
                    cost = Decimal(row["provider_cost_usd"])
                except Exception as exc:
                    raise SQLiteTraceStoreError("persisted provider cost is invalid") from exc
                if not cost.is_finite() or cost < 0:
                    raise SQLiteTraceStoreError("persisted provider cost is invalid")
                successful_costs.append(cost)
            elif status == "ESCALATED":
                escalated_count += 1
            else:
                raise SQLiteTraceStoreError("persisted terminal status is invalid")
        return FailureFingerprintHistory(
            fingerprint_digest=fingerprint_digest,
            seen_count=len(rows),
            successful_count=successful_count,
            escalated_count=escalated_count,
            lowest_success_cost_usd=min(successful_costs) if successful_costs else None,
            latest_trace_id=rows[0]["trace_id"],
        )
