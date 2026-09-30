import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))

from probe_inspector_sonnet_4_6_access import MODEL, PROFILE, REGION, probe


class Bedrock:
    def get_foundation_model_availability(self, *, modelId):
        self.availability_model = modelId
        return {
            'modelId': MODEL,
            'agreementAvailability': {'status': 'NOT_AVAILABLE'},
            'authorizationStatus': 'AUTHORIZED',
            'entitlementAvailability': 'AVAILABLE',
            'regionAvailability': 'AVAILABLE',
        }

    def list_foundation_model_agreement_offers(self, *, modelId, offerType):
        self.offer = (modelId, offerType)
        return {'modelId': MODEL, 'offers': [{'offerToken': 'secret-token'}]}

    def get_inference_profile(self, *, inferenceProfileIdentifier):
        self.profile = inferenceProfileIdentifier
        return {
            'inferenceProfileId': PROFILE,
            'status': 'ACTIVE',
            'type': 'SYSTEM_DEFINED',
            'models': [{'modelArn': 'arn:aws:bedrock:::foundation-model/' + MODEL}],
        }

    def get_use_case_for_model_access(self):
        return {'formData': b'private use case'}


class Factory:
    def __init__(self):
        self.client = Bedrock()

    def __call__(self, service, *, region_name):
        self.request = (service, region_name)
        return self.client


class Sonnet46AccessProbeTests(unittest.TestCase):
    def test_probe_is_read_only_and_redacts_offer_and_use_case(self):
        factory = Factory()
        result = probe(factory)
        self.assertEqual(factory.request, ('bedrock', REGION))
        self.assertEqual(result['model'], MODEL)
        self.assertEqual(result['profile'], PROFILE)
        self.assertEqual(result['public_offer_count'], 1)
        self.assertTrue(result['anthropic_use_case_present'])
        self.assertEqual(result['model_calls'], 0)
        self.assertFalse(result['task_material_sent'])
        self.assertFalse(result['access_changed'])
        self.assertNotIn('offerToken', str(result))
        self.assertNotIn('private use case', str(result))


if __name__ == '__main__':
    unittest.main()
