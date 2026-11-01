"""Local host composition. Construction never reads credentials or dispatches.

The trusted caller supplies admitted task, immutable source, approved limits and
adapters. This is not an authorization endpoint or a deployed scheduler.
"""
import json
import os
from pathlib import Path

from factory_state.model import StateError
from .development_provider import DevelopmentProviderSession, ExclusiveDevelopmentJournal
from .development_runner import DevelopmentTaskRunner
from .task_queue import LocalTaskQueue
from .worker import digest


class DevelopmentHost:
    def __init__(self, directory, *, task, contract_bytes, snapshot, builder,
                 reviewer, target, builder_cap, reviewer_cap, total_cap,
                 request_for, sandbox_for, clock, enabled=False, delivery=None,
                 repair_rounds=0):
        if type(enabled) is not bool:
            raise StateError('explicit boolean activation required')
        task.validate()
        spec = json.loads(contract_bytes)
        if (task.contract_digest != digest(contract_bytes)
                or task.task_id != spec['task_id']
                or task.expected_state != 'IMPLEMENTATION'
                or snapshot.repository != spec['repository']
                or snapshot.commit != spec['target_commit']
                or any(spec.get(k) is not False for k in (
                    'execution_authorized', 'spending_authorized',
                    'signing_authorized', 'release_authorized'))):
            raise StateError('host requires an exact inert task and repository binding')
        # Validate adapters and caps before consuming the fresh directory.
        session = DevelopmentProviderSession(builder=builder, reviewer=reviewer,
            target=target, builder_cap=builder_cap, reviewer_cap=reviewer_cap,
            total_cap=total_cap, journal=None, enabled=enabled, repair_rounds=repair_rounds)
        self.directory = Path(directory)
        if not self.directory.parent.is_dir() or self.directory.parent.is_symlink():
            raise StateError('existing regular attempt parent required')
        # A partial or uncertain previous construction is never reused.
        self.directory.mkdir(exist_ok=False)
        session.journal = ExclusiveDevelopmentJournal(self.directory)
        self.queue = LocalTaskQueue(self.directory / 'queue.db')
        self.queue.enqueue(task)
        def save_named(filename, entry_id, raw):
            if entry_id != task.entry_id:
                raise StateError('artifact entry differs from admitted task')
            with (self.directory / filename).open('xb') as handle:
                handle.write(raw)
                handle.flush()
                os.fsync(handle.fileno())
        self.runner = DevelopmentTaskRunner(self.queue,
            contract_bytes=contract_bytes, snapshot=snapshot,
            builder=session.build, reviewer=session.review,
            request_for=request_for, sandbox_for=sandbox_for,
            save_artifact=lambda entry, raw: save_named('attempt.json', entry, raw),
            save_test_evidence=lambda entry, raw: save_named('tests.json', entry, raw), clock=clock,
            builder_identity='development-builder',
            reviewer_identity='development-reviewer', enabled=enabled, delivery=delivery,
            repair_rounds=repair_rounds, repair_builder=session.repair_build,
            repair_reviewer=session.repair_review,
            save_repair_test_evidence=lambda entry, raw: save_named('repair-tests.json', entry, raw))
        # Only this new attempt's local queue can be enabled by the trusted host.
        self.queue.pause(not enabled)

    async def tick(self):
        return await self.runner.tick()
