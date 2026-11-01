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
from .openai_provider import OpenAIResponsesProviderInvoker, OpenAIProviderProtocolError, PROVIDER_FAILURE_CODES
from .worker import digest


STAGES = ('builder', 'reviewer', 'repair_builder', 'repair_reviewer',
          'repair2_builder', 'repair2_reviewer')


class ExclusiveDevelopmentJournal:
    """One directory per approved attempt; an existing start is never overwritten."""
    def __init__(self, directory):
        self.directory = Path(directory)
        if not self.directory.is_dir():
            raise StateError('existing attempt journal directory required')

    def __call__(self, event, evidence):
        if event not in {f'{stage}.{state}' for stage in STAGES
                         for state in ('started', 'completed', 'failed')}:
            raise StateError('unknown development journal event')
        raw = canonical(evidence)
        with (self.directory / (event + '.json')).open('xb') as handle:
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())


class DevelopmentProviderSession:
    def __init__(self, *, builder, reviewer, target, builder_cap, reviewer_cap,
                 total_cap, journal, enabled=False, repair_rounds=0):
        caps = (builder_cap, reviewer_cap, total_cap)
        if type(repair_rounds) is not int or repair_rounds not in (0, 1, 2):
            raise StateError('at most two bounded repair rounds')
        if any(type(v) is not Decimal or not v.is_finite() or v <= 0 for v in caps):
            raise StateError('finite positive stage and total caps required')
        # Each round may spend both stage caps; the total covers every round.
        if (builder_cap + reviewer_cap) * (1 + repair_rounds) > total_cap or type(enabled) is not bool:
            raise StateError('stage caps exceed total or activation is invalid')
        for adapter, workload in ((builder, 'task_implementation'), (reviewer, 'task_review')):
            if (not isinstance(adapter, OpenAIResponsesProviderInvoker)
                    or adapter.policy.workload != workload):
                raise StateError('separate workload-specific OpenAI adapters required')
        if builder is reviewer or target.provider_family != 'openai':
            raise StateError('one provider with separate builder and reviewer required')
        self.repair_rounds = repair_rounds
        self.adapters = {stage: builder if stage.endswith('builder') else reviewer for stage in STAGES}
        self.caps = {stage: builder_cap if stage.endswith('builder') else reviewer_cap for stage in STAGES}
        self.target, self.journal, self.enabled = target, journal, enabled
        self.started, self.completed = set(), set()
        self.builder_input_digest = self.builder_decision_digest = None
        self.repair_decision_digest = None
        self.repair_decision_digests = {}

    async def build(self, turn):
        return await self._call('builder', 'factory_task_implementation_v1', turn)

    async def review(self, turn):
        return await self._call('reviewer', 'factory_task_review_v1', turn)

    async def repair_build(self, turn):
        repair = turn.get('repair') if type(turn) is dict else None
        number = repair.get('round') if type(repair) is dict else None
        if number not in (1, 2):
            raise StateError('repair round required')
        return await self._call('repair_builder' if number == 1 else 'repair2_builder',
                                'factory_task_implementation_v1', turn)

    async def repair_review(self, turn, round=1):
        if round not in (1, 2):
            raise StateError('repair round required')
        return await self._call('repair_reviewer' if round == 1 else 'repair2_reviewer',
                                'factory_task_review_v1', turn)

    async def _call(self, stage, kind, turn):
        if not self.enabled:
            raise StateError('development provider session disabled')
        # A repair may follow a review rejection or failed checks; it still binds the builder result.
        prerequisite = {'builder': None, 'reviewer': 'builder', 'repair_builder': 'builder',
                        'repair_reviewer': 'repair_builder', 'repair2_builder': 'repair_builder',
                        'repair2_reviewer': 'repair2_builder'}[stage]
        needed = 2 if stage.startswith('repair2') else 1 if stage.startswith('repair') else 0
        if (stage in self.started or (prerequisite and prerequisite not in self.completed)
                or self.repair_rounds < needed):
            raise StateError('stage consumed, prerequisite incomplete or repair not approved')
        if type(turn) is not dict or turn.get('kind') != kind:
            raise StateError('provider turn kind differs')
        bound = {'reviewer': self.builder_decision_digest,
                 'repair_reviewer': self.repair_decision_digests.get(1),
                 'repair2_reviewer': self.repair_decision_digests.get(2)}
        if stage in bound and (turn.get('candidate_input_digest') != self.builder_input_digest
                or turn.get('candidate_decision_digest') != bound[stage]):
            raise StateError('review must bind this session builder result')
        rejected = {'repair_builder': self.builder_decision_digest,
                    'repair2_builder': self.repair_decision_digests.get(1)}
        if stage in rejected and (type(turn.get('repair')) is not dict
                or turn['repair'].get('rejected_decision_digest') != rejected[stage]):
            raise StateError('repair must bind the rejected builder result')
        frozen = canonical(turn)
        # Set before any await; durable exclusive journal must succeed before IO.
        self.started.add(stage)
        binding = {'stage': stage, 'input_digest': digest(frozen),
                   'model_id': self.target.model_id, 'max_cost_usd': str(self.caps[stage])}
        self.journal(stage + '.started', binding)
        try:
            result = await self.adapters[stage].invoke(target=self.target,
                turn=json.loads(frozen), max_cost_usd=self.caps[stage], decision_schema_version='1')
        except Exception as exc:
            code = exc.failure_code if isinstance(exc, OpenAIProviderProtocolError) else 'protocol_failure'
            self.journal(stage + '.failed', {**binding,
                'failure_code': code if code in PROVIDER_FAILURE_CODES else 'protocol_failure',
                'response_evidence': dict(self.adapters[stage].last_response_evidence),
                'billing_reconciled': False})
            raise
        decision_bytes = canonical(result.decision)
        self.journal(stage + '.completed', {**binding,
            'decision_digest': digest(decision_bytes),
            # Retain bounded normalized proposals, not the raw vendor response.
            # This is untrusted evidence, never execution or release authority.
            'proposal': json.loads(decision_bytes) if len(decision_bytes) <= 32000 else None,
            'proposal_bytes': len(decision_bytes), 'authoritative': False,
            'input_tokens': result.input_tokens, 'output_tokens': result.output_tokens,
            'cost_usd': str(result.cost_usd)})
        self.completed.add(stage)
        if stage == 'builder':
            self.builder_input_digest = digest(frozen)
            self.builder_decision_digest = digest(decision_bytes)
        elif stage in ('repair_builder', 'repair2_builder'):
            number = 1 if stage == 'repair_builder' else 2
            self.repair_decision_digests[number] = self.repair_decision_digest = digest(decision_bytes)
        return json.loads(decision_bytes)
