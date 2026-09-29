"""Owner-gated acceptance tick; the deployment supplies the durable scheduler.

This service does not create jobs, signatures, credentials, or infrastructure.
The disabled Lambda stays inert until a separately reviewed composition supplies
state, immutable job material, scoped receipts, and a pinned role executor.
"""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from factory_state.model import StateError

from .autonomy import AutonomyActivation, AutonomousScheduler
from .autonomy_contract import load_autonomy_operating_allowance


class AcceptanceController:
    def __init__(self, root: Path, activation: AutonomyActivation, scheduler: AutonomousScheduler,
                 *, deployed_commit: str, clock=None, enabled=False):
        if type(enabled) is not bool:
            raise StateError('acceptance controller activation must be explicit')
        self.root = Path(root)
        self.activation, self.scheduler = activation, scheduler
        self.deployed_commit = deployed_commit
        self.clock = clock or (lambda: datetime.now(timezone.utc))
        self.enabled = enabled

    def tick(self, event):
        if not self.enabled:
            raise StateError('acceptance controller is disabled')
        expected = {'factory_id': 'tims-software-factory',
                    'task_id': 'deterministic-text-fingerprint', 'mode': 'acceptance'}
        if not isinstance(event, dict) or event != expected:
            raise StateError('acceptance controller event differs from the exact task')
        allowance = load_autonomy_operating_allowance(self.root)
        if (not allowance.activation_ready or allowance.production_release_authorized or
                allowance.acceptance_task_id != expected['task_id'] or
                allowance.target_alias != 'coding_primary_sol_live' or
                allowance.model_id != 'gpt-5.6-sol' or
                not isinstance(self.activation, AutonomyActivation) or
                self.activation.factory_id != expected['factory_id'] or
                self.activation.task_id != allowance.acceptance_task_id or
                self.activation.source_commit != self.deployed_commit or
                self.activation.contract_digest != 'sha256:' + allowance.acceptance_contract_sha256 or
                not isinstance(self.scheduler, AutonomousScheduler) or
                self.scheduler.activation != self.activation or
                self.scheduler.enabled is not True):
            raise StateError('acceptance controller lacks the exact active deployment')
        now = self.clock()
        self.activation.validate(now)
        if not allowance.pricing_observed_at <= now < allowance.pricing_expires_at:
            raise StateError('acceptance controller pricing is stale')
        result = self.scheduler.tick(expected['factory_id'], expected['task_id'])
        if (result.get('release_dispatched') is not False or
                type(result.get('worker_invocations')) is not int or
                result['worker_invocations'] not in (0, 1)):
            raise StateError('acceptance controller result exceeds authority')
        return result
