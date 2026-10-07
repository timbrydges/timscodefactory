from dataclasses import replace
from types import SimpleNamespace
import unittest
from unittest.mock import Mock

from factory_runtime.review_verdict import ReviewBinding
from factory_runtime.security_verdict import SecurityReviewBinding, BoundSecurityValidator
from factory_state.model import StateError
from factory_state.scope import canonical


class SecurityVerdictTests(unittest.TestCase):
    def setUp(self):
        self.qa = ReviewBinding('factory', 'task', 'qa_engineer', 'a'*40,
            'sha256:'+'b'*64, 'sha256:'+'c'*64, 'd'*40, 'sha256:'+'e'*64,
            'sha256:'+'f'*64, ('fingerprint.py',))
        self.binding = SecurityReviewBinding(self.qa, 'sha256:'+'1'*64,
            'sha256:'+'2'*64, 'sha256:'+'3'*64)
        self.tests = Mock(return_value=True)
        self.prerequisites = Mock(return_value=True)
        self.validator = BoundSecurityValidator(self.binding, self.tests, self.prerequisites)
        self.state = SimpleNamespace(factory_id='factory', task_id='task', state='SECURITY_REVIEW',
            leases=[SimpleNamespace(lease_id='lease', role_id='deep_security_reviewer')])
        self.request = SimpleNamespace(source_commit=self.qa.source_commit,
            contract_digest=self.qa.contract_digest, input_digest=self.binding.input_digest,
            lease_id='lease')
        self.report = {key: getattr(self.qa, key) for key in self.qa.__dataclass_fields__
                       if key != 'allowed_paths'}
        self.report.update(kind='factory_security_review_v1', role_id='deep_security_reviewer',
            input_digest=self.binding.input_digest, qa_result_digest=self.binding.qa_result_digest,
            security_scope_digest=self.binding.security_scope_digest,
            verdict='ACCEPTED', rationale='Reviewed within the exact signed scope.', findings=[])

    def validate(self, **changes):
        return self.validator(self.state, self.request, canonical({**self.report, **changes}))

    def test_acceptance_requires_both_independent_verifiers(self):
        self.assertTrue(self.validate())
        self.tests.assert_called_once_with(self.qa.candidate_commit, self.qa.candidate_digest,
                                          self.qa.test_evidence_digest)
        self.prerequisites.assert_called_once_with(self.binding)
        for callback in (self.tests, self.prerequisites):
            for answer in (False, None, 1, 'verified'):
                callback.return_value = answer
                self.assertFalse(self.validate())
            callback.return_value = True

    def test_no_risk_severity_can_be_waived_by_model(self):
        for severity in ('low', 'medium', 'high', 'critical', 'accepted', None, []):
            self.assertFalse(self.validate(findings=[{'severity': severity,
                'path': 'fingerprint.py', 'detail': 'Unresolved risk'}]))
        self.tests.assert_not_called()
        self.assertTrue(self.validate(findings=[{'severity': 'info',
            'path': 'fingerprint.py', 'detail': 'Reviewed fixed source.'}]))
        self.assertFalse(self.validate(findings=[{'severity': 'info', 'path': 'fingerprint.py',
            'detail': 'Risk', 'waived': True}]))

    def test_every_pin_and_untrusted_authority_claim_fails_closed(self):
        for key in self.report:
            if key not in ('rationale', 'findings'):
                with self.subTest(key=key):
                    self.assertFalse(self.validate(**{key: 'other'}))
        for extra in ('production_release_authorized', 'tests_passed', 'gate_authority'):
            self.assertFalse(self.validate(**{extra: True}))
        self.tests.assert_not_called()
        self.prerequisites.assert_not_called()

    def test_malformed_nested_and_duplicate_data_rejected(self):
        raw = canonical(self.report)
        for bad in (b'[]', b'null', raw[:-1]+b',"verdict":"ACCEPTED"}',
                    b'{"x":NaN}', b'\xff', b'x'*32769, raw.decode().encode('utf-16')):
            self.assertFalse(self.validator(self.state, self.request, bad))
        for changes in ({'rationale': ' '}, {'findings': {}}, {'findings': [None]},
                {'findings': [{'severity':'info', 'path':'../secret', 'detail':'x'}]},
                {'findings': [{'severity':'info', 'path':'fingerprint.py', 'detail':' '}]}):
            self.assertFalse(self.validate(**changes))
        self.tests.assert_not_called()

    def test_wrong_stage_lease_or_input_never_checks_evidence(self):
        self.state.state = 'QA'; self.assertFalse(self.validate())
        self.state.state = 'SECURITY_REVIEW'
        self.state.leases[0].role_id = 'qa_engineer'; self.assertFalse(self.validate())
        self.state.leases[0].role_id = 'deep_security_reviewer'
        self.state.leases *= 2; self.assertFalse(self.validate())
        self.state.leases = self.state.leases[:1]
        self.request.input_digest = self.qa.input_digest; self.assertFalse(self.validate())
        self.tests.assert_not_called()

    def test_configuration_cannot_reuse_qa_input_or_other_role(self):
        for binding in (None, replace(self.binding, input_digest=self.qa.input_digest),
                replace(self.binding, qa=replace(self.qa, role_id='independent_inspector')),
                replace(self.binding, qa_result_digest='historical'),
                replace(self.binding, security_scope_digest='synthetic')):
            with self.assertRaises(StateError):
                BoundSecurityValidator(binding, self.tests, self.prerequisites)
        with self.assertRaises(StateError):
            BoundSecurityValidator(self.binding, self.tests, None)


if __name__ == '__main__':
    unittest.main()
