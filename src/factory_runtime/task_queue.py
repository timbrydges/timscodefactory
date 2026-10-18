"""Local durable queue for one existing scheduler tick per entry.

Queue records are routing data, never approval. Deployment supplies the scheduler
and its existing authorization/budget gates. No cloud adapter or timer is created.
STARTED entries are deliberately never reclaimed after interruption.
"""
from dataclasses import asdict, dataclass
from contextlib import contextmanager
import json
from pathlib import Path
import sqlite3
import hashlib
import re

from factory_state.model import COMMIT_SHA, SAFE_IDENTIFIER, SHA256_DIGEST, StateError


@dataclass(frozen=True)
class QueuedTask:
    entry_id: str
    factory_id: str
    task_id: str
    activation_id: str
    source_commit: str
    contract_digest: str
    expected_state: str | None = None

    def validate(self):
        for value in (self.entry_id, self.factory_id, self.task_id, self.activation_id):
            if not isinstance(value, str) or not SAFE_IDENTIFIER.fullmatch(value):
                raise StateError('invalid task queue identity')
        if (not isinstance(self.source_commit, str) or not COMMIT_SHA.fullmatch(self.source_commit)
                or not isinstance(self.contract_digest, str)
                or not SHA256_DIGEST.fullmatch(self.contract_digest)):
            raise StateError('task queue requires exact source and contract pins')
        if self.expected_state is not None and self.expected_state not in {'IMPLEMENTATION', 'INSPECTION', 'QA'}:
            raise StateError('unsupported queued progression stage')


class LocalTaskQueue:
    """SQLite on a local persistent volume; not a distributed cloud queue.

    Pause prevents new claims; it cannot cancel an already running external call.
    Existing worker/adapters must still enforce their own pause and spend gates.
    """
    def __init__(self, path):
        self.path = Path(path)
        if (self.path.is_symlink() or not self.path.parent.is_dir()
                or self.path.parent.is_symlink()):
            raise StateError('queue requires a regular local database path')
        with self._connect() as db:
            db.execute('CREATE TABLE IF NOT EXISTS controls (id INTEGER PRIMARY KEY CHECK(id=1), paused INTEGER NOT NULL)')
            db.execute('INSERT OR IGNORE INTO controls VALUES (1, 1)')
            db.execute('''CREATE TABLE IF NOT EXISTS tasks (
                entry_id TEXT PRIMARY KEY, binding TEXT NOT NULL UNIQUE,
                status TEXT NOT NULL, result TEXT)''')
            db.execute('CREATE TABLE IF NOT EXISTS plans (plan_id TEXT PRIMARY KEY, binding TEXT NOT NULL)')
            db.execute('CREATE TABLE IF NOT EXISTS dependencies (entry_id TEXT PRIMARY KEY, predecessor TEXT NOT NULL UNIQUE)')
            db.execute('CREATE TABLE IF NOT EXISTS admissions (receipt_id TEXT PRIMARY KEY, plan_id TEXT NOT NULL UNIQUE, receipt TEXT NOT NULL)')

    @contextmanager
    def _connect(self):
        db = sqlite3.connect(self.path, timeout=5)
        try:
            with db:
                yield db
        finally:
            db.close()

    def enqueue(self, task):
        task.validate()
        binding = json.dumps(asdict(task), sort_keys=True)
        with self._connect() as db:
            db.execute('BEGIN IMMEDIATE')
            old = db.execute('SELECT binding FROM tasks WHERE entry_id=?', (task.entry_id,)).fetchone()
            if old:
                if old[0] != binding:
                    raise StateError('queue entry binding cannot change')
                return  # Re-enqueue never resets a consumed entry.
            db.execute('INSERT INTO tasks VALUES (?, ?, ?, NULL)', (task.entry_id, binding, 'PENDING'))

    def pause(self, paused=True):
        if type(paused) is not bool:
            raise StateError('pause must be boolean')
        with self._connect() as db:
            db.execute('UPDATE controls SET paused=? WHERE id=1', (int(paused),))

    def enqueue_plan(self, plan_id, *, repository, target_commit, contract_bytes, tasks, admission=None):
        """Pin a linear development plan atomically; still grants no authority.

        Only IMPLEMENTATION -> INSPECTION -> QA is admitted in this first slice.
        A later stage waits for a successfully advanced predecessor, never a retry.
        """
        if (not isinstance(plan_id, str) or not SAFE_IDENTIFIER.fullmatch(plan_id)
                or not isinstance(repository, str)
                or not re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', repository)
                or not isinstance(target_commit, str) or not COMMIT_SHA.fullmatch(target_commit)
                or not isinstance(contract_bytes, bytes) or len(contract_bytes) > 65536):
            raise StateError('invalid immutable plan binding')
        spec = json.loads(contract_bytes)
        if (spec.get('repository') != repository or spec.get('target_commit') != target_commit
                or any(spec.get(k) is not False for k in ('execution_authorized', 'spending_authorized',
                                                          'signing_authorized', 'release_authorized'))):
            raise StateError('plan must bind an inert repository specification')
        if len(tasks) != 3 or [t.expected_state for t in tasks] != ['IMPLEMENTATION', 'INSPECTION', 'QA']:
            raise StateError('plan requires the exact development stage sequence')
        contract_digest = 'sha256:' + hashlib.sha256(contract_bytes).hexdigest()
        for task in tasks:
            task.validate()
            if (task.contract_digest != contract_digest or task.task_id != spec.get('task_id')
                    or any(getattr(task, field) != getattr(tasks[0], field)
                           for field in ('factory_id', 'task_id', 'activation_id', 'source_commit'))):
                raise StateError('plan stages differ from pinned task binding')
        if len({t.entry_id for t in tasks}) != 3:
            raise StateError('plan entries must be distinct')
        binding = json.dumps({'repository': repository, 'target_commit': target_commit,
            'contract_digest': contract_digest, 'tasks': [asdict(t) for t in tasks]}, sort_keys=True)
        with self._connect() as db:
            db.execute('BEGIN IMMEDIATE')
            old = db.execute('SELECT binding FROM plans WHERE plan_id=?', (plan_id,)).fetchone()
            if old:
                if old[0] != binding:
                    raise StateError('plan binding cannot change')
                if admission is not None:
                    saved = db.execute('SELECT receipt_id,receipt FROM admissions WHERE plan_id=?', (plan_id,)).fetchone()
                    if saved != admission:
                        raise StateError('plan admission cannot change or be added retroactively')
                return
            if admission is not None:
                db.execute('INSERT INTO admissions VALUES (?,?,?)', (admission[0], plan_id, admission[1]))
            db.execute('INSERT INTO plans VALUES (?,?)', (plan_id, binding))
            for index, task in enumerate(tasks):
                db.execute('INSERT INTO tasks VALUES (?,?,?,NULL)',
                           (task.entry_id, json.dumps(asdict(task), sort_keys=True), 'PENDING'))
                if index:
                    db.execute('INSERT INTO dependencies VALUES (?,?)', (task.entry_id, tasks[index-1].entry_id))

    def admission_for(self, task):
        with self._connect() as db:
            row = db.execute('''SELECT a.receipt FROM admissions a
                JOIN plans p ON p.plan_id=a.plan_id, json_each(p.binding,'$.tasks') t
                WHERE json_extract(t.value,'$.entry_id')=?''', (task.entry_id,)).fetchone()
        if row is None:
            raise StateError('queue entry has no authenticated admission')
        return json.loads(row[0])

    def claim(self):
        with self._connect() as db:
            db.execute('BEGIN IMMEDIATE')
            if db.execute('SELECT paused FROM controls WHERE id=1').fetchone()[0]:
                return None
            row = db.execute("""SELECT t.entry_id,t.binding FROM tasks t
                LEFT JOIN dependencies d ON d.entry_id=t.entry_id
                LEFT JOIN tasks p ON p.entry_id=d.predecessor
                WHERE t.status='PENDING' AND (d.entry_id IS NULL OR
                (p.status='TICK_COMPLETED' AND json_extract(p.result,'$.scheduler_status')
                    IN ('ADVANCED','ALREADY_ADVANCED')))
                ORDER BY t.rowid LIMIT 1""").fetchone()
            if row is None:
                return None
            task = QueuedTask(**json.loads(row[1]))
            task.validate()
            if task.entry_id != row[0]:
                raise StateError('queue binding corrupted')
            db.execute("UPDATE tasks SET status='STARTED' WHERE entry_id=?", (row[0],))
            return task

    def finish(self, entry_id, status, result):
        if status not in {'TICK_COMPLETED', 'REJECTED', 'STOPPED', 'NEEDS_RECONCILIATION'}:
            raise StateError('invalid queue outcome')
        with self._connect() as db:
            changed = db.execute("UPDATE tasks SET status=?,result=? WHERE entry_id=? AND status='STARTED'",
                                 (status, json.dumps(result, sort_keys=True), entry_id)).rowcount
            if changed != 1:
                raise StateError('queue result requires an unfinished claim')

    def inspect(self, entry_id):
        with self._connect() as db:
            row = db.execute('SELECT status,result FROM tasks WHERE entry_id=?', (entry_id,)).fetchone()
        return None if row is None else {'status': row[0], 'result': json.loads(row[1]) if row[1] else None}


class GenericTaskRunner:
    def __init__(self, queue, scheduler_for, *, enabled=False):
        if type(enabled) is not bool:
            raise StateError('runner activation must be explicit')
        self.queue, self.scheduler_for, self.enabled = queue, scheduler_for, enabled

    def tick(self):
        if not self.enabled:
            return {'status': 'DISABLED'}
        task = self.queue.claim()
        if task is None:
            return {'status': 'IDLE_OR_PAUSED'}
        try:
            scheduler = self.scheduler_for(task)  # Trusted composition, not a module name from task data.
            activation = scheduler.activation
            for field in ('factory_id', 'task_id', 'activation_id', 'source_commit', 'contract_digest'):
                if getattr(activation, field) != getattr(task, field):
                    raise StateError('queued task differs from scheduler activation')
            # Check against the same state snapshot used to select the job, not
            # a separate read that could become stale before scheduler.tick().
            options = {} if task.expected_state is None else {'expected_state': task.expected_state}
            result = scheduler.tick(task.factory_id, task.task_id, **options)
            if (not isinstance(result, dict) or result.get('release_dispatched') is not False
                    or type(result.get('worker_invocations')) is not int
                    or not 0 <= result['worker_invocations'] <= 1):
                raise StateError('scheduler returned invalid bounded result')
            state = result.get('status')
            outcome = ('TICK_COMPLETED' if state in {'ADVANCED', 'ALREADY_ADVANCED', 'RELEASE_READY'}
                       else state if state in {'REJECTED', 'STOPPED'} else 'NEEDS_RECONCILIATION')
            # Persist bounded metadata only, not arbitrary provider output or exceptions.
            summary = {'scheduler_status': state if isinstance(state, str) and len(state) <= 80 else 'INVALID',
                       'worker_invocations': result['worker_invocations'], 'release_dispatched': False}
        except Exception as error:
            outcome = 'NEEDS_RECONCILIATION'
            summary = {'error_type': type(error).__name__}
        self.queue.finish(task.entry_id, outcome, summary)
        return {'entry_id': task.entry_id, 'status': outcome, 'result': summary}
