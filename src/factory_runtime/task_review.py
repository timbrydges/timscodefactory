"""Bound, non-authoritative review packets; no calls, signatures or progression."""
import json

from factory_state.model import SAFE_IDENTIFIER, StateError
from factory_state.scope import canonical
from .worker import digest


class TaskReviewProtocol:
    def __init__(self, protocol, decision, candidate, request, receipt, *,
                 builder_identity, reviewer_identity, now):
        # Identities and receipt provenance come from trusted deployment, never
        # from provider output. Distinct labels do not establish authentication.
        if (any(not isinstance(v, str) or not SAFE_IDENTIFIER.fullmatch(v)
                for v in (builder_identity, reviewer_identity))
                or builder_identity == reviewer_identity):
            raise StateError('review requires distinct trusted builder and reviewer identities')
        decision = json.loads(canonical(decision))
        checked = protocol.validate_decision(decision)
        if (decision.get('type') != 'apply_edits' or checked['input_digest'] != candidate.input_digest
                or checked['decision_digest'] != candidate.decision_digest):
            raise StateError('review proposal differs from candidate')
        observation = candidate.evaluate(request, receipt, now=now)
        if observation['status'] != 'TESTS_PASSED_REVIEW_REQUIRED':
            raise StateError('review requires a bound successful test observation')
        turn = protocol.turn
        # One change per path: several edits to a file apply in order, as in the candidate.
        after, order = {}, []
        for edit in decision['edits']:
            path, before = edit['path'], turn['files'].get(edit['path'])
            if path not in after:
                order.append(path)
            current = after.get(path, before)
            after[path] = (edit['new_text'] if before is None else
                           current.replace(edit['old_text'], edit['new_text'], 1))
        changes = [{'path': p, 'before': turn['files'].get(p), 'after': after[p]} for p in order]
        packet = {'kind': 'factory_task_review_v1', 'repository': turn['repository'],
            'target_commit': turn['target_commit'], 'task_id': turn['task_id'],
            'specification': turn['specification'], 'builder_identity': builder_identity,
            'reviewer_identity': reviewer_identity, 'candidate_input_digest': candidate.input_digest,
            'candidate_decision_digest': candidate.decision_digest,
            'workspace_digest': candidate.workspace_digest, 'test_request_digest': request.request_digest,
            'stdout_digest': receipt.stdout_digest, 'stderr_digest': receipt.stderr_digest,
            'changes': changes}
        self._raw = canonical(packet)
        if len(self._raw) > 64000:
            raise StateError('review packet exceeds byte limit')

    @property
    def input_digest(self):
        return digest(self._raw)

    @property
    def turn(self):
        return {**json.loads(self._raw), 'review_input_digest': self.input_digest}

    def validate_decision(self, decision, *, reviewer_identity):
        turn = self.turn
        if (reviewer_identity != turn['reviewer_identity'] or type(decision) is not dict
                or set(decision) != {'review_input_digest', 'verdict', 'findings'}
                or decision['review_input_digest'] != self.input_digest
                or decision['verdict'] not in ('APPROVE', 'REJECT')
                or type(decision['findings']) is not list or len(decision['findings']) > 50
                or any(type(v) is not str or not v.strip() for v in decision['findings'])
                or (decision['verdict'] == 'APPROVE' and decision['findings'])
                or (decision['verdict'] == 'REJECT' and not decision['findings'])
                or len(canonical(decision)) > 16000):
            raise StateError('review decision is invalid or differs from bound packet')
        return {'status': 'REVIEW_ACCEPTED' if decision['verdict'] == 'APPROVE' else 'REVIEW_REJECTED',
            'review_input_digest': self.input_digest, 'review_decision_digest': digest(canonical(decision)),
            'workspace_digest': turn['workspace_digest'], 'authoritative': False,
            'progression_authorized': False, 'release_authorized': False}
