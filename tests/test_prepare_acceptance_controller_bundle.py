import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / 'scripts'), str(ROOT / 'src'), str(ROOT / 'tests')]

from factory_runtime.acceptance_jobs import encode_job
from factory_runtime.worker import digest
from factory_state.model import StateError
from prepare_acceptance_controller_bundle import build_bundle
from test_acceptance_jobs import material


class BundleTests(unittest.TestCase):
    def setUp(self):
        activation, job, _ = material()
        self.raw = encode_job(job, activation.activation_id)
        self.binding = {'activation_id': activation.activation_id,
            'source_commit': activation.source_commit,
            'contract_digest': activation.contract_digest,
            'starts_at': activation.starts_at.isoformat(),
            'expires_at': activation.expires_at.isoformat(),
            'builder_version_arn': 'arn:aws:lambda:ca-central-1:666730517561:function:tims-factory-builder:8',
            'job_version_id': 'job-version'}

    def test_policy_and_runtime_config_share_job_and_receipt_pins(self):
        result = build_bundle(self.binding, self.raw)
        config = result['controller_config']
        policy = result['policy']['Statement']
        self.assertEqual(result['status'], 'PREPARED_NOT_DEPLOYED')
        self.assertEqual(result['model_calls_authorized'], 0)
        self.assertEqual(config['job_versions']['IMPLEMENTATION'],
            {'version_id': 'job-version', 'sha256': digest(self.raw)})
        self.assertEqual(policy[2]['Condition']['StringEquals']['s3:VersionId'],
                         config['job_versions']['IMPLEMENTATION']['version_id'])
        self.assertEqual(policy[3]['Condition']['StringEquals']['s3:VersionId'], 'owner-v1')
        self.assertEqual(policy[4]['Condition']['StringEquals']['s3:VersionId'], 'review-v1')
        self.assertEqual(policy[5]['Resource'], config['builder_version_arn'])

    def test_tampering_and_mismatched_deployment_fail_closed(self):
        document = json.loads(self.raw)
        cases = [(dict(self.binding, activation_id='other'), self.raw),
                 (dict(self.binding, contract_digest='sha256:' + 'b' * 64), self.raw),
                 (dict(self.binding, builder_version_arn=self.binding['builder_version_arn'][:-1] + 'x'), self.raw),
                 (self.binding, json.dumps({**document, 'plan_digest': digest(b'other')}).encode()),
                 (self.binding, json.dumps({**document, 'receipt_versions':
                                          {'owner': 'null', 'reviewer': 'review-v1'}}).encode())]
        for changed, raw in cases:
            with self.subTest(changed=changed, raw=raw[:40]), self.assertRaises((StateError, ValueError)):
                build_bundle(changed, raw)


if __name__ == '__main__':
    unittest.main()
