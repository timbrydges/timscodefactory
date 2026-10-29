import unittest
from factory_runtime.identity_diagnostics import IdentityFailure, failure_receipt

class SafeDiagnosticsTests(unittest.TestCase):
    def test_arbitrary_values_are_not_exported(self):
        for value in ('secret-token', [], {}, None):
            error = IdentityFailure(value, value)
            self.assertEqual(failure_receipt(error), {'failure_stage': 'unknown', 'failure_reason': 'unknown'})
            self.assertNotIn('secret-token', str(error))

    def test_exception_message_is_never_exported(self):
        receipt = failure_receipt(RuntimeError('secret-token'))
        self.assertNotIn('secret-token', str(receipt))
        self.assertEqual(receipt['failure_stage'], 'unknown')

    def test_mutated_fields_are_sanitized_again(self):
        error = IdentityFailure('github_http', 'http_error')
        error.stage = 'secret-token'
        error.reason = {'secret': 'token'}
        self.assertEqual(failure_receipt(error), {'failure_stage': 'unknown', 'failure_reason': 'unknown'})
