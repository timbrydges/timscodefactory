"""Single-provider development callbacks; no transport or live activation supplied.

The trusted host owns authorization, credentials, pricing and an exclusive durable
journal. A started stage is never retried, including after an uncertain response.
"""
from decimal import Decimal
import json
import os
from pathlib import Path

from factory_state.model import StateError
from factory_state.scope import canonical
from .openai_provider import OpenAIResponsesProviderInvoker
from .worker import digest


class ExclusiveDevelopmentJournal:
    """One directory per approved attempt; an existing start is never overwritten."""
    def __init__(self, directory):
        self.directory = Path(directory)
        if not self.directory.is_dir():
            raise StateError('existing attempt journal directory required')

    def __call__(self, event, evidence):
        if event not in {'builder.started', 'builder.completed',
                         'reviewer.started', 'reviewer.completed'}:
            raise StateError('unknown development journal event')
        raw = canonical(evidence)
        with (self.directory / (event + '.json')).open('xb') as handle:
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())


class DevelopmentProviderSession:
    def __init__(self, *, builder, reviewer, target, builder_cap, reviewer_cap,
                 total_cap, journal, enabled=False):
        caps = (builder_cap, reviewer_cap, total_cap)
        if any(type(v) is not Decimal or not v.is_finite() or v <= 0 for v in caps):
            raise StateError('finite positive stage and total caps required')
        if builder_cap + reviewer_cap > total_cap or type(enabled) is not bool:
            raise StateError('stage caps exceed total or activation is invalid')
        for adapter, workload in ((builder, 'task_implementation'), (reviewer, 'task_review')):
            if (not isinstance(adapter, OpenAIResponsesProviderInvoker)
                    or adapter.policy.workload != workload):
                raise StateError('separate workload-specific OpenAI adapters required')
        if builder is reviewer or target.provider_family != 'openai':
            raise StateError('one provider with separate builder and reviewer required')
        self.adapters = {'builder': builder, 'reviewer': reviewer}
        self.caps = {'builder': builder_cap, 'reviewer': reviewer_cap}
        self.target, self.journal, self.enabled = target, journal, enabled
        self.started, self.completed = set(), set()
        self.builder_input_digest = self.builder_decision_digest = None

    async def build(self, turn):
        return await self._call('builder', 'factory_task_implementation_v1', turn)

    async def review(self, turn):
        return await self._call('reviewer', 'factory_task_review_v1', turn)

    async def _call(self, stage, kind, turn):
        if not self.enabled:
            raise StateError('development provider session disabled')
        if stage in self.started or (stage == 'reviewer' and 'builder' not in self.completed):
            raise StateError('stage consumed or builder incomplete')
        if type(turn) is not dict or turn.get('kind') != kind:
            raise StateError('provider turn kind differs')
        if stage == 'reviewer' and (
                turn.get('candidate_input_digest') != self.builder_input_digest
                or turn.get('candidate_decision_digest') != self.builder_decision_digest):
            raise StateError('review must bind this session builder result')
        frozen = canonical(turn)
        # Set before any await; durable exclusive journal must succeed before IO.
        self.started.add(stage)
        binding = {'stage': stage, 'input_digest': digest(frozen),
                   'model_id': self.target.model_id, 'max_cost_usd': str(self.caps[stage])}
        self.journal(stage + '.started', binding)
        result = await self.adapters[stage].invoke(target=self.target,
            turn=json.loads(frozen), max_cost_usd=self.caps[stage], decision_schema_version='1')
        self.journal(stage + '.completed', {**binding,
            'decision_digest': digest(canonical(result.decision)),
            'input_tokens': result.input_tokens, 'output_tokens': result.output_tokens,
            'cost_usd': str(result.cost_usd)})
        self.completed.add(stage)
        if stage == 'builder':
            self.builder_input_digest = digest(frozen)
            self.builder_decision_digest = digest(canonical(result.decision))
        return result.decision
