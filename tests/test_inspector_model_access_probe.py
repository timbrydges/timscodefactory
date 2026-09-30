import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))

from probe_acceptance_inspector_model_access import CANDIDATES, inventory


class ModelAccessProbeTests(unittest.TestCase):
    def test_only_control_plane_availability_for_exact_candidates(self):
        calls = []

        class AnyModelClient:
            def get_foundation_model_availability(self, *, modelId):
                return {'modelId': modelId, 'agreementAvailability': {'status': 'AVAILABLE'},
                        'authorizationStatus': 'NOT_AUTHORIZED',
                        'entitlementAvailability': 'NOT_AVAILABLE',
                        'regionAvailability': 'AVAILABLE'}

        result = inventory(lambda service, region_name: (
            calls.append((service, region_name)) or AnyModelClient()))
        self.assertEqual(calls, [('bedrock', region) for region, _ in CANDIDATES])
        self.assertEqual([item['model'] for item in result['candidates']],
                         [model for _, model in CANDIDATES])
        self.assertTrue(all(item['authorization'] == 'NOT_AUTHORIZED'
                            for item in result['candidates']))
        self.assertEqual(result['model_calls'], 0)
        self.assertFalse(result['access_changed'])


if __name__ == '__main__':
    unittest.main()
