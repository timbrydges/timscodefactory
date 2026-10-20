"""Durable local scheduling, below the approval boundary; no timer installation.

Only trusted operator code admits packet digests and supplies load/dispatch
callbacks. Dispatch must independently validate the exact live approval. A
schedule record never grants spending or execution authority.
"""
from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
from pathlib import Path
import re
import sqlite3
import uuid

from factory_state.model import StateError


def _time(value):
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise StateError('aware schedule timestamp required')
    return value.astimezone(timezone.utc).timestamp()


class DevelopmentSchedule:
    def __init__(self, path):
        self.path = Path(path)
        if (self.path.is_symlink() or self.path.parent.is_symlink()
                or not self.path.parent.is_dir()):
            raise StateError('regular local schedule path required')
        with self._db() as db:
            db.execute('CREATE TABLE IF NOT EXISTS schedule_controls (id INTEGER PRIMARY KEY CHECK(id=1), paused INTEGER NOT NULL)')
            db.execute('INSERT OR IGNORE INTO schedule_controls VALUES (1,1)')
            db.execute("""CREATE TABLE IF NOT EXISTS schedule_jobs (
                job_id TEXT PRIMARY KEY, packet_digest TEXT NOT NULL UNIQUE,
                due REAL NOT NULL, expires REAL NOT NULL, status TEXT NOT NULL,
                claim TEXT, result TEXT)""")

    @contextmanager
    def _db(self):
        db = sqlite3.connect(self.path, timeout=5)
        try:
            with db:
                yield db
        finally:
            db.close()

    def admit(self, job_id, packet_digest, *, due_at, expires_at, operator_authorized=False):
        if operator_authorized is not True:
            raise StateError('trusted operator admission required')
        if (type(job_id) is not str or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._:-]{0,127}', job_id)
                or type(packet_digest) is not str
                or not re.fullmatch(r'sha256:[0-9a-f]{64}', packet_digest)):
            raise StateError('exact schedule binding required')
        due, expiry = _time(due_at), _time(expires_at)
        if not due < expiry:
            raise StateError('schedule must precede expiry')
        with self._db() as db:
            db.execute('BEGIN IMMEDIATE')
            old = db.execute('SELECT packet_digest,due,expires FROM schedule_jobs WHERE job_id=?', (job_id,)).fetchone()
            binding = (packet_digest, due, expiry)
            if old:
                if old != binding:
                    raise StateError('schedule binding cannot change')
                return  # Never reset a started or terminal job.
            if db.execute('SELECT COUNT(*) FROM schedule_jobs').fetchone()[0] >= 1000:
                raise StateError('schedule capacity reached')
            db.execute('INSERT INTO schedule_jobs VALUES (?,?,?,?,?,NULL,NULL)',
                       (job_id, packet_digest, due, expiry, 'PENDING'))

    def pause(self, paused=True):
        if type(paused) is not bool:
            raise StateError('boolean schedule pause required')
        with self._db() as db:
            db.execute('UPDATE schedule_controls SET paused=? WHERE id=1', (int(paused),))

    def claim_due(self, *, now):
        current = _time(now)
        with self._db() as db:
            db.execute('BEGIN IMMEDIATE')
            if db.execute('SELECT paused FROM schedule_controls WHERE id=1').fetchone()[0]:
                return None
            db.execute("UPDATE schedule_jobs SET status='EXPIRED' WHERE status='PENDING' AND expires<=?", (current,))
            row = db.execute("""SELECT job_id,packet_digest,expires FROM schedule_jobs
                WHERE status='PENDING' AND due<=? ORDER BY due,job_id LIMIT 1""", (current,)).fetchone()
            if row is None:
                return None
            token = uuid.uuid4().hex
            db.execute("UPDATE schedule_jobs SET status='STARTED',claim=? WHERE job_id=?", (token,row[0]))
            return {'job_id':row[0], 'packet_digest':row[1], 'expires':row[2], 'claim':token}

    def finish(self, claim, result):
        if result not in {'COMPLETED','REJECTED','NEEDS_RECONCILIATION','EXPIRED'}:
            raise StateError('unsupported terminal schedule result')
        with self._db() as db:
            changed = db.execute("""UPDATE schedule_jobs SET status=?,result=?
                WHERE job_id=? AND claim=? AND status='STARTED'""",
                (result,result,claim['job_id'],claim['claim'])).rowcount
            if changed != 1:
                raise StateError('schedule claim is not active')

    def status(self, job_id):
        with self._db() as db:
            row = db.execute('SELECT status FROM schedule_jobs WHERE job_id=?',(job_id,)).fetchone()
            return row[0] if row else None


async def scheduled_tick(schedule, *, load_packet, dispatch, clock, enabled=False):
    """One claim; callback failures are terminal, never automatically retried.

    No dynamic imports, executable selection or credential names come from this
    table. The fixed dispatch callback must enforce approval, source and budget.
    """
    if type(enabled) is not bool:
        raise StateError('explicit scheduler activation required')
    if not enabled:
        return {'status':'DISABLED'}
    claim = schedule.claim_due(now=clock())
    if claim is None:
        return {'status':'IDLE_OR_PAUSED'}
    result = 'NEEDS_RECONCILIATION'
    try:
        packet = load_packet(claim['job_id'])
        if (type(packet) is not bytes or len(packet) > 262144
                or 'sha256:'+hashlib.sha256(packet).hexdigest() != claim['packet_digest']):
            result = 'REJECTED'
        elif _time(clock()) >= claim['expires']:
            result = 'EXPIRED'
        else:
            outcome = await dispatch(packet)
            if outcome == 'TICK_COMPLETED':
                result = 'COMPLETED'
            elif outcome == 'REJECTED':
                result = 'REJECTED'
    except Exception:
        # Never retain exceptions that may contain credentials or provider bodies.
        result = 'NEEDS_RECONCILIATION'
    schedule.finish(claim, result)
    return {'job_id':claim['job_id'], 'status':result}
