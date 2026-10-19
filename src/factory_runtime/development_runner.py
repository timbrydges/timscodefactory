"""One claimed development attempt: proposal -> isolated tests -> review artifact.

Trusted composition supplies adapters and authorizations; queue data cannot select
commands, credentials or modules. No production state, PR publishing or retries.
The executable composition shipped with this module is offline replay only.
"""
from dataclasses import asdict
import json

from factory_state.model import StateError
from factory_state.scope import canonical
from .task_candidate import candidate_workspace
from .task_provider import TaskImplementationProtocol
from .task_review import TaskReviewProtocol
from .worker import digest


class DevelopmentTaskRunner:
    def __init__(self, queue, *, contract_bytes, snapshot, builder, reviewer,
                 request_for, sandbox_for, save_artifact, clock,
                 builder_identity, reviewer_identity, enabled=False):
        if type(enabled) is not bool or builder_identity == reviewer_identity:
            raise StateError('explicit activation and distinct identities required')
        self.queue, self.enabled = queue, enabled
        self.contract_bytes, self.snapshot = contract_bytes, snapshot
        self.builder, self.reviewer = builder, reviewer
        self.request_for, self.sandbox_for = request_for, sandbox_for
        self.save_artifact, self.clock = save_artifact, clock
        self.builder_identity, self.reviewer_identity = builder_identity, reviewer_identity

    async def tick(self):
        if not self.enabled:
            return {'status': 'DISABLED'}
        task = self.queue.claim()  # Durable before any external work. Never reclaim.
        if task is None:
            return {'status': 'IDLE_OR_PAUSED'}
        phase = 'BINDING'
        try:
            spec = json.loads(self.contract_bytes)
            source = {f.path: f.content for f in self.snapshot.files}
            files = {p: source[p].decode('utf-8') for p in spec['allowed_paths'] if p in source}
            missing = [p for p in spec['allowed_paths'] if p not in source]
            protocol = TaskImplementationProtocol(task, repository=self.snapshot.repository,
                target_commit=self.snapshot.commit, contract_bytes=self.contract_bytes,
                files=files, missing_paths=missing)
            phase = 'BUILDER'
            decision = json.loads(canonical(await self.builder(protocol.turn)))
            protocol.validate_decision(decision)
            if decision['type'] != 'apply_edits':
                result = {'status': 'NEEDS_INPUT', 'decision_type': decision['type']}
                outcome = 'STOPPED'
            else:
                phase = 'CANDIDATE'
                with candidate_workspace(protocol, decision, repository_snapshot=self.snapshot) as candidate:
                    request = self.request_for(candidate)
                    phase = 'TESTS'
                    receipt = await self.sandbox_for(candidate).execute(request)
                    observation = candidate.evaluate(request, receipt, now=self.clock())
                    artifact = {'kind': 'development_attempt_v1', 'entry_id': task.entry_id,
                        'proposal': decision, 'test_observation': observation,
                        'test_request': asdict(request), 'test_receipt': asdict(receipt),
                        'authoritative': False, 'release_authorized': False}
                    result = observation
                    outcome = 'REJECTED'
                    if observation['status'] == 'TESTS_PASSED_REVIEW_REQUIRED':
                        phase = 'REVIEW'
                        review = TaskReviewProtocol(protocol, decision, candidate, request, receipt,
                            builder_identity=self.builder_identity, reviewer_identity=self.reviewer_identity,
                            now=self.clock())
                        review_decision = json.loads(canonical(await self.reviewer(review.turn)))
                        result = review.validate_decision(review_decision, reviewer_identity=self.reviewer_identity)
                        # Reject adapters that mutate the source while reviewing.
                        candidate.evaluate(request, receipt, now=self.clock())
                        artifact.update(review_packet=review.turn, review_decision=review_decision)
                        outcome = 'TICK_COMPLETED' if result['status'] == 'REVIEW_ACCEPTED' else 'REJECTED'
                    artifact['result'] = result
                    phase = 'ARTIFACT'
                    # Sink must persist exclusively; failure leaves an uncertain consumed attempt.
                    raw = json.dumps(artifact, sort_keys=True, default=lambda v: v.isoformat()).encode('utf-8')
                    self.save_artifact(task.entry_id, raw)
                    result = {**result, 'artifact_digest': digest(raw)}
            result = {**result, 'authoritative': False, 'release_authorized': False}
        except Exception as error:
            outcome = 'NEEDS_RECONCILIATION'
            result = {'status': outcome, 'phase': phase, 'error_type': type(error).__name__}
        self.queue.finish(task.entry_id, outcome, result)
        return {'entry_id': task.entry_id, 'status': outcome, 'result': result}
