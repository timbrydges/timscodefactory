"""Separate security semantics; no dispatch, signing, spending or release grant.

Bindings and verifiers are privileged deployment inputs, never model output.
Historical synthetic security receipts are deliberately not loaded here.
"""
from dataclasses import dataclass
import json
import re

from factory_state.model import StateError
from .review_verdict import ReviewBinding


@dataclass(frozen=True)
class SecurityReviewBinding:
    qa: ReviewBinding
    input_digest: str
    qa_result_digest: str
    security_scope_digest: str

    def validate(self):
        if type(self.qa) is not ReviewBinding or self.qa.role_id != 'qa_engineer':
            raise StateError('Exact deployment-owned QA prerequisite required')
        self.qa.validate()
        for value in (self.input_digest, self.qa_result_digest, self.security_scope_digest):
            if type(value) is not str or not re.fullmatch('sha256:[0-9a-f]{64}', value):
                raise StateError('Exact security input, QA result and scope pins required')
        if self.input_digest == self.qa.input_digest:
            raise StateError('Security requires a separate input binding')


class BoundSecurityValidator:
    """Validate report semantics after external signature/lease authentication.

    The prerequisite callback must authenticate the exact QA result and current
    security scope. A digest or model assertion alone is never that authority.
    The proof callback must check independently authenticated fresh test bytes.
    Neither callback nor successful validation grants production release.
    """
    def __init__(self, binding, verify_tests, verify_prerequisites):
        if (type(binding) is not SecurityReviewBinding or not callable(verify_tests)
                or not callable(verify_prerequisites)):
            raise StateError('Deployment-owned security binding and verifiers required')
        binding.validate()
        self.binding = binding
        self.verify_tests = verify_tests
        self.verify_prerequisites = verify_prerequisites

    def __call__(self, state, request, output):
        b = self.binding
        q = b.qa
        if ((state.factory_id, state.task_id, state.state) !=
                (q.factory_id, q.task_id, 'SECURITY_REVIEW') or
                (request.source_commit, request.contract_digest, request.input_digest) !=
                (q.source_commit, q.contract_digest, b.input_digest)):
            return False
        leases = [lease for lease in state.leases if lease.lease_id == request.lease_id]
        if len(leases) != 1 or leases[0].role_id != 'deep_security_reviewer':
            return False
        if type(output) is not bytes or not 0 < len(output) <= 32768:
            return False

        def unique(pairs):
            result = {}
            for key, value in pairs:
                if key in result:
                    raise ValueError('Duplicate security field')
                result[key] = value
            return result

        def invalid_constant(_):
            raise ValueError('Non-finite security value')

        try:
            value = json.loads(output.decode('utf-8'), object_pairs_hook=unique,
                               parse_constant=invalid_constant)
        except (ValueError, UnicodeError, RecursionError):
            return False
        expected = {
            'kind': 'factory_security_review_v1', 'role_id': 'deep_security_reviewer',
            'factory_id': q.factory_id, 'task_id': q.task_id,
            'source_commit': q.source_commit, 'contract_digest': q.contract_digest,
            'input_digest': b.input_digest, 'candidate_commit': q.candidate_commit,
            'candidate_digest': q.candidate_digest,
            'test_evidence_digest': q.test_evidence_digest,
            'qa_result_digest': b.qa_result_digest,
            'security_scope_digest': b.security_scope_digest,
        }
        if (type(value) is not dict or
                set(value) != set(expected) | {'verdict', 'rationale', 'findings'} or
                any(value[key] != item for key, item in expected.items()) or
                value['verdict'] != 'ACCEPTED' or
                type(value['rationale']) is not str or
                not 1 <= len(value['rationale'].strip()) <= 2000 or
                type(value['findings']) is not list or len(value['findings']) > 16):
            return False
        # Every unresolved risk blocks this initial security gate. An info-only
        # observation cannot claim remediation, waiver or accepted-risk authority.
        for finding in value['findings']:
            if (type(finding) is not dict or set(finding) != {'severity', 'path', 'detail'} or
                    finding['severity'] != 'info' or finding['path'] not in q.allowed_paths or
                    type(finding['detail']) is not str or
                    not 1 <= len(finding['detail'].strip()) <= 1000):
                return False
        return (self.verify_tests(q.candidate_commit, q.candidate_digest,
                                  q.test_evidence_digest) is True and
                self.verify_prerequisites(b) is True)
