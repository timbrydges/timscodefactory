import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / 'scripts'), str(ROOT / 'src'), str(ROOT / 'tests')]

from factory_runtime.inspector_assessment import parse_assessment
from factory_state.model import StateError
from prepare_acceptance_inspector_prompt import render
from prepare_acceptance_inspector_review import build_packet
from test_acceptance_jobs import NOW
from test_prepare_acceptance_job import fixtures


class InspectorAssessmentTests(unittest.TestCase):
    def pending(self):
        binding, plan, _, input_bytes, contract_bytes = fixtures()
        packet = build_packet(binding, plan, input_bytes, contract_bytes, now=NOW)
        request = render(packet)
        material = json.loads(request['user'])
        response = {key: material[key] for key in
                    ('plan_digest', 'input_digest', 'contract_digest')}
        response.update(verdict='REJECTED', rationale='Contract omits required evidence',
                        evidence=['Missing signed result'])
        return request, response

    def test_rejection_is_bound_evidence_without_authority(self):
        request, response = self.pending()
        assessment = parse_assessment(json.dumps(response).encode(), request)
        self.assertEqual(assessment.verdict, 'REJECTED')
        self.assertEqual(assessment.plan_digest, request['plan_digest'])
        self.assertEqual(assessment.status, 'UNAUTHENTICATED_ASSESSMENT')
        self.assertFalse(hasattr(assessment, 'signature'))

    def test_acceptance_is_still_untrusted_evidence(self):
        request, response = self.pending()
        response['verdict'] = 'ACCEPTED'
        self.assertEqual(parse_assessment(json.dumps(response).encode(), request).status,
                         'UNAUTHENTICATED_ASSESSMENT')

    def test_changed_binding_unexpected_fields_and_duplicate_keys_fail(self):
        request, response = self.pending()
        mutations = ({**response, 'plan_digest': 'sha256:' + '0' * 64},
                     {**response, 'signature': 'pretend'},
                     {**response, 'verdict': 'APPROVED'},
                     {**response, 'evidence': []})
        for changed in mutations:
            with self.subTest(changed=changed), self.assertRaises(StateError):
                parse_assessment(json.dumps(changed).encode(), request)
        raw = json.dumps(response)[:-1] + ',"verdict":"ACCEPTED"}'
        with self.assertRaises(StateError):
            parse_assessment(raw.encode(), request)

    def test_field_diagnostics_keep_bounds_and_do_not_echo_model_text(self):
        request, response = self.pending()
        cases = (
            ({'verdict': 'PRIVATE_MODEL_TEXT'}, 'invalid verdict enum'),
            ({'rationale': 'x' * 2001}, 'rationale length=2001'),
            ({'rationale': '   '}, 'rationale length=0'),
            ({'evidence': ['PRIVATE_MODEL_TEXT'] * 9}, 'evidence count=9'),
            ({'evidence': ['x' * 501]}, 'evidence[0] length=501'),
            ({'evidence': [123]}, 'evidence[0] must be a string'),
        )
        for change, diagnostic in cases:
            with self.subTest(diagnostic=diagnostic):
                with self.assertRaises(StateError) as caught:
                    parse_assessment(json.dumps({**response, **change}).encode(), request)
                self.assertIn(diagnostic, str(caught.exception))
                self.assertNotIn('PRIVATE_MODEL_TEXT', str(caught.exception))
                self.assertNotIn('x' * 20, str(caught.exception))
        response.update(rationale='x' * 2000, evidence=['y' * 500] * 8)
        self.assertEqual(parse_assessment(json.dumps(response).encode(), request).verdict,
                         'REJECTED')


if __name__ == '__main__':
    unittest.main()
