import base64
from dataclasses import replace
from datetime import timedelta
import tempfile
import unittest

from factory_runtime.security_provider_scope import SecurityProviderScope, verify
from factory_runtime.security_verdict import SecurityReviewBinding
from factory_runtime.review_verdict import ReviewBinding
from factory_runtime.worker import digest
from factory_runtime.security_policy import policy_digest
from factory_state.dispatch import DispatchRequest
from factory_state.model import StateError
from factory_state.scope import canonical
from scripts.scope_dispatch_canary import fixture_keys, sign
from test_autonomous_scheduler import NOW


def fixture():
    request = DispatchRequest('security004', 'bounded-review-004', 'bounded-security',
        'a'*40, digest(b'contract'), digest(b'security input'))
    qa = ReviewBinding('tims-software-factory', 'bounded-review-004', 'qa_engineer',
        request.source_commit, request.contract_digest, digest(b'QA input'), 'b'*40,
        digest(b'candidate'), digest(b'tests'), ('fingerprint.py',))
    binding = SecurityReviewBinding(qa, request.input_digest, digest(b'QA result'), policy_digest())
    scope = SecurityProviderScope(binding, request, b'exact security provider request')
    times = {'issued_at': int(NOW.timestamp())-1, 'expires_at': int(NOW.timestamp())+600}
    pricing = {'kind': 'bounded_security004_rate_qualification', **scope.bindings(),
        'currency': 'USD', 'complete_request_bound_qualified': True,
        'standard_text_only_no_cache_rates': True, 'input_token_bound': 32768,
        'output_token_bound': 4096, 'input_micro_usd_per_million': 3000000,
        'output_micro_usd_per_million': 15000000, 'evidence_digest': digest(b'test quote'), **times}
    ready = {'kind': 'bounded_security004_provider_readiness', **scope.bindings(),
        'credential_route_verified': True, 'model_metadata_verified': True,
        'repository_binding_verified': True, 'single_attempt_failure_risk_accepted': True,
        'evidence_digest': digest(b'test readiness'), **times}
    payload = {'kind': 'bounded_security004_provider_allowance', 'owner_identity': 'tim_brydges',
        **scope.bindings(), 'pricing_digest': digest(canonical(pricing)),
        'readiness_digest': digest(canonical(ready)), 'reserved_micro_usd': 250000,
        'aggregate_ceiling_micro_usd': 3500000, 'maximum_provider_calls': 1,
        'retries': 0, 'production_release_authorized': False, **times}
    return scope, pricing, ready, payload


class SecurityScopeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.keys, self.private = fixture_keys(self.temp.name)

    def verify(self, scope, pricing, readiness, payload, *, signer='tim_brydges', now=NOW, keys=None):
        envelope = {'payload': payload, 'signature_base64': base64.b64encode(
            sign(payload, self.private[signer], self.temp.name)).decode()}
        return verify(envelope, scope=scope, pricing=pricing, readiness=readiness, now=now,
                      trusted_keys=self.keys if keys is None else keys)

    def test_fixed_separate_security_scope_and_cost(self):
        scope, price, ready, payload = fixture()
        result = self.verify(scope, price, ready, payload)
        self.assertEqual(result.maximum_cost_micro_usd, 159744)
        self.assertEqual(scope.bindings()['claim_key'], 'BOUNDED_SECURITY#004#ROLE#security')
        self.assertEqual(payload['reserved_micro_usd'], 250000)

    def test_owner_signature_and_freshness_required(self):
        for changes in ({'signer': 'independent_inspector_service'}, {'keys': {}},
                        {'now': NOW+timedelta(minutes=11)}):
            with self.assertRaises(StateError): self.verify(*fixture(), **changes)

    def test_old_allowances_and_changed_limits_cannot_authorize_security(self):
        for changes in ({'kind': 'bounded_review004_provider_allowance'},
                {'claim_key': 'BOUNDED_REVIEW#004#ROLE#inspector'}, {'role': 'inspector'},
                {'reserved_micro_usd': 250001}, {'aggregate_ceiling_micro_usd': 3250000},
                {'aggregate_ceiling_micro_usd': 3500001}, {'maximum_provider_calls': True},
                {'retries': 1}, {'production_release_authorized': True}):
            scope, price, ready, payload = fixture()
            with self.subTest(changes=changes), self.assertRaises(StateError):
                self.verify(scope, price, ready, {**payload, **changes})

    def test_candidate_qa_proof_scope_and_request_substitution_blocked(self):
        scope, price, ready, payload = fixture()
        for changed in (replace(scope, request_bytes=b'changed'),
                replace(scope, binding=replace(scope.binding, qa_result_digest=digest(b'other'))),
                replace(scope, binding=replace(scope.binding, security_scope_digest=digest(b'other'))),
                replace(scope, request=replace(scope.request, lease_id='other')),
                replace(scope, binding=replace(scope.binding,
                    qa=replace(scope.binding.qa, candidate_commit='c'*40)))):
            with self.assertRaises(StateError): self.verify(changed, price, ready, payload)

    def test_signed_bad_pricing_or_readiness_still_fails(self):
        for target, change in (('price', {'input_token_bound': True}),
                ('price', {'input_micro_usd_per_million': 1000000000}),
                ('price', {'complete_request_bound_qualified': False}),
                ('ready', {'credential_route_verified': False})):
            scope, price, ready, payload = fixture()
            (price if target == 'price' else ready).update(change)
            payload.update(pricing_digest=digest(canonical(price)), readiness_digest=digest(canonical(ready)))
            with self.assertRaises(StateError): self.verify(scope, price, ready, payload)


if __name__ == '__main__': unittest.main()
