import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))

from probe_acceptance_inspector_agreement import MODEL, diagnose


class InspectorAgreementProbeTests(unittest.TestCase):
    def test_reads_only_and_omits_form_and_offer_token(self):
        calls = []

        class Client:
            def get_use_case_for_model_access(self):
                calls.append(('get_use_case_for_model_access',))
                return {'formData': b'private use case'}

            def list_foundation_model_agreement_offers(self, **kwargs):
                calls.append(('list_foundation_model_agreement_offers', kwargs))
                return {'modelId': MODEL, 'offers': [
                    {'offerToken': 'private token', 'termDetails': {
                        'legalTerm': {'url': 'https://example.org/terms'}}}]}

        result = diagnose(Client())
        self.assertEqual(calls, [
            ('get_use_case_for_model_access',),
            ('list_foundation_model_agreement_offers',
             {'modelId': MODEL, 'offerType': 'PUBLIC'})])
        self.assertTrue(result['anthropic_use_case_present'])
        self.assertEqual(result['public_offer_count'], 1)
        self.assertNotIn('legal_terms_urls', result)
        self.assertNotIn('private', str(result))
        self.assertFalse(result['access_changed'])


if __name__ == '__main__':
    unittest.main()
