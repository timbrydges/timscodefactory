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
from .anthropic_provider import AnthropicMessagesReviewInvoker
from .google_review_provider import GoogleQAReviewInvoker
from .openai_provider import OpenAIResponsesProviderInvoker, OpenAIProviderProtocolError, PROVIDER_FAILURE_CODES
from .worker import digest


STAGES = ('builder', 'reviewer', 'qa', 'repair_builder', 'repair_reviewer', 'repair_qa',
          'repair2_builder', 'repair2_reviewer', 'repair2_qa')


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
                 total_cap, journal, enabled=False, repair_rounds=0, reviewer_target=None,
                 qa=None, qa_target=None, qa_cap=None):
        caps = (builder_cap, reviewer_cap, total_cap, *((qa_cap,) if qa is not None else ()))
        if type(repair_rounds) is not int or repair_rounds not in (0, 1, 2):
            raise StateError('at most two bounded repair rounds')
        if any(type(v) is not Decimal or not v.is_finite() or v <= 0 for v in caps):
            raise StateError('finite positive stage and total caps required')
        # Each round may spend both stage caps; the total covers every round.
        round_cap = builder_cap + reviewer_cap + (qa_cap if qa is not None else 0)
        if round_cap * (1 + repair_rounds) > total_cap or type(enabled) is not bool:
            raise StateError('stage caps exceed total or activation is invalid')
        if (not isinstance(builder, OpenAIResponsesProviderInvoker)
                or builder.policy.workload != 'task_implementation' or target.provider_family != 'openai'):
            raise StateError('workload-specific OpenAI builder required')
        if reviewer_target is None:
            # Legacy single-provider review: separate adapter, same family.
            if (not isinstance(reviewer, OpenAIResponsesProviderInvoker)
                    or reviewer.policy.workload != 'task_review' or builder is reviewer):
                raise StateError('one provider with separate builder and reviewer required')
            reviewer_target = target
        elif (reviewer_target.provider_family == target.provider_family
                or reviewer_target.model_id == target.model_id
                or reviewer_target.provider_family != 'anthropic'
                or not isinstance(reviewer, AnthropicMessagesReviewInvoker)):
            # Hard rule: an independent reviewer never shares the builder's provider family.
            raise StateError('independent reviewer must come from a different provider family')
        if qa is not None and (qa_target is None or reviewer_target is target
                or qa_target.provider_family != 'google'
                or qa_target.provider_family in (target.provider_family, reviewer_target.provider_family)
                or not isinstance(qa, GoogleQAReviewInvoker)):
            # QA is a third provider family, after an independent Inspector.
            raise StateError('QA reviewer must be Google, after an independent Inspector')
        if qa is None and qa_target is not None:
            raise StateError('QA target without a QA adapter')
        self.qa = qa
        pick = lambda stage, b, r, q: b if stage.endswith('builder') else q if stage.endswith('qa') else r
        self.targets = {stage: pick(stage, target, reviewer_target, qa_target) for stage in STAGES}
        self.repair_rounds = repair_rounds
        self.adapters = {stage: pick(stage, builder, reviewer, qa) for stage in STAGES}
        self.caps = {stage: pick(stage, builder_cap, reviewer_cap, qa_cap) for stage in STAGES}
        self.target, self.journal, self.enabled = target, journal, enabled
        self.started, self.completed = set(), set()
        self.builder_input_digest = self.builder_decision_digest = None
        self.repair_decision_digest = None
        self.repair_decision_digests = {}

    async def build(self, turn):
        return await self._call('builder', 'factory_task_implementation_v1', turn)

    async def review(self, turn):
        return await self._reviewed('reviewer', 'qa', turn)

    async def _reviewed(self, inspector, qa, turn):
        """Inspector first; QA only after an approval. Both must approve."""
        decision = await self._call(inspector, 'factory_task_review_v1', turn)
        if self.qa is None or decision.get('verdict') != 'APPROVE':
            return decision
        verdict = await self._call(qa, 'factory_task_review_v1', turn)
        if verdict.get('verdict') == 'APPROVE':
            return decision
        findings = [f'QA: {f}' for f in verdict.get('findings', []) if isinstance(f, str)]
        return {'review_input_digest': decision['review_input_digest'], 'verdict': 'REJECT',
                'findings': findings or ['QA: rejected without findings']}

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
        prefix = 'repair_' if round == 1 else 'repair2_'
        return await self._reviewed(prefix + 'reviewer', prefix + 'qa', turn)

    async def _call(self, stage, kind, turn):
        if not self.enabled:
            raise StateError('development provider session disabled')
        # A repair may follow a review rejection or failed checks; it still binds the builder result.
        prerequisite = {'builder': None, 'reviewer': 'builder', 'repair_builder': 'builder',
                        'repair_reviewer': 'repair_builder', 'repair2_builder': 'repair_builder',
                        'repair2_reviewer': 'repair2_builder', 'qa': 'reviewer',
                        'repair_qa': 'repair_reviewer', 'repair2_qa': 'repair2_reviewer'}[stage]
        needed = 2 if stage.startswith('repair2') else 1 if stage.startswith('repair') else 0
        if (stage in self.started or (prerequisite and prerequisite not in self.completed)
                or self.repair_rounds < needed):
            raise StateError('stage consumed, prerequisite incomplete or repair not approved')
        if type(turn) is not dict or turn.get('kind') != kind:
            raise StateError('provider turn kind differs')
        bound = {'reviewer': self.builder_decision_digest, 'qa': self.builder_decision_digest,
                 'repair_reviewer': self.repair_decision_digests.get(1),
                 'repair_qa': self.repair_decision_digests.get(1),
                 'repair2_reviewer': self.repair_decision_digests.get(2),
                 'repair2_qa': self.repair_decision_digests.get(2)}
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
                   'provider_family': self.targets[stage].provider_family,
                   'model_id': self.targets[stage].model_id, 'max_cost_usd': str(self.caps[stage])}
        self.journal(stage + '.started', binding)
        try:
            result = await self.adapters[stage].invoke(target=self.targets[stage],
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
