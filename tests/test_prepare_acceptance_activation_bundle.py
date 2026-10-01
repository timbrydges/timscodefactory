import json
import sys
import unittest
from datetime import timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / 'src'), str(ROOT / 'scripts'), str(ROOT / 'tests')]

from factory_runtime.autonomy_contract import load_autonomy_operating_allowance
from factory_runtime.intake import IntakePlan
from factory_runtime.receipt_transport import receipt_plan_digest
from factory_runtime.worker import digest
from factory_state.dispatch import DispatchRequest, DynamoDBDispatchStore
from factory_state.model import Lease, StateError
from prepare_acceptance_activation_bundle import build_activation_bundle
from prepare_acceptance_job import prepare
from test_prepare_acceptance_job import fixtures


class ActivationBundleTests(unittest.TestCase):
    def material(self):
        binding, plan, versions, _, _ = fixtures()
        allowance = load_autonomy_operating_allowance(ROOT)
        now = allowance.pricing_observed_at + timedelta(minutes=1)
        task_input = (ROOT / 'factory/autonomy/acceptance-input.txt').read_bytes()
        contract = (ROOT / 'factory/autonomy/acceptance-contract.json').read_bytes()
        binding.update(contract_digest=digest(contract), starts_at=now.isoformat(),
                       expires_at=(now + timedelta(hours=1)).isoformat())
        plan['lease']['expires_at'] = (now + timedelta(minutes=30)).isoformat()
        plan['request'].update(contract_digest=digest(contract), input_digest=digest(task_input))
        plan['capability_payload']['contract_digest'] = digest(contract)
        plan['review_payload']['binding'] = DynamoDBDispatchStore._binding(DispatchRequest(**plan['request']))
        for payload in (plan['capability_payload'], plan['review_payload']):
            payload.update(issued_at=int(now.timestamp()),
                           expires_at=int((now + timedelta(minutes=20)).timestamp()))
        restored = IntakePlan(plan['factory_id'], plan['task_id'], plan['state'], plan['state_version'],
            Lease(**{**plan['lease'], 'expires_at': now + timedelta(minutes=30)}),
            DispatchRequest(**plan['request']), plan['capability_payload'], plan['review_payload'])
        plan['plan_digest'] = receipt_plan_digest(restored)
        raw, _ = prepare(binding, plan, versions, task_input, contract, now=now)
        binding.update(job_version_id='job-v1',
            broker_version_arn='arn:aws:lambda:ca-central-1:666730517561:function:tims-factory-provider-broker:6',
            provider_secret_arn='arn:aws:secretsmanager:ca-central-1:666730517561:secret:tims-software-factory/provider/openai/acceptance-ABC123')
        return binding, raw, now

    def test_pending_gates_never_become_activation_authority(self):
        binding, raw, now = self.material()
        result = build_activation_bundle(binding, raw, now=now)
        self.assertFalse(result['activation_authorized'])
        self.assertEqual(result['model_calls_authorized'], 0)
        self.assertIn('operating_contract_not_active', result['contract_blockers'])
        env = result['environment_updates']
        self.assertEqual(env['builder']['FACTORY_OPERATIONAL_EXECUTION_ENABLED'], 'false')
        self.assertEqual(env['broker']['FACTORY_ACCEPTANCE_BROKER_ENABLED'], 'false')
        self.assertEqual(env['controller']['FACTORY_AUTONOMY_CONTROLLER_ENABLED'], 'false')
        configs = [json.loads(env[role][key]) for role, key in (
            ('broker', 'FACTORY_ACCEPTANCE_ACTIVATION_JSON'),
            ('builder', 'FACTORY_ACCEPTANCE_ACTIVATION_JSON'),
            ('controller', 'FACTORY_ACCEPTANCE_CONTROLLER_JSON'))]
        for key, value in configs[0].items():
            self.assertEqual([config[key] for config in configs], [value] * 3)
        self.assertEqual(configs[1]['broker_version_arn'], binding['broker_version_arn'])
        self.assertEqual(configs[2]['builder_version_arn'], binding['builder_version_arn'])
        self.assertEqual(configs[2]['job_versions']['IMPLEMENTATION']['sha256'], digest(raw))

    def test_rejects_stale_receipts_even_while_activation_remains_current(self):
        binding, raw, now = self.material()
        with self.assertRaisesRegex(StateError, 'receipts'):
            build_activation_bundle(binding, raw, now=now + timedelta(minutes=21))

    def test_rejects_unpublished_pins_cross_account_alias_and_source_drift(self):
        binding, raw, now = self.material()
        for changes in (
            {'job_version_id': 'NOT_PUBLISHED'}, {'job_version_id': 'null'},
            {'broker_version_arn': binding['broker_version_arn'].replace(':6', ':acceptance')},
            {'provider_secret_arn': binding['provider_secret_arn'].replace('666730517561', '111111111111')},
            {'source_commit': 'b' * 40}, {'unexpected': 'value'},
        ):
            with self.subTest(changes=changes), self.assertRaises((StateError, ValueError)):
                build_activation_bundle({**binding, **changes}, raw, now=now)

    def test_rejects_activation_outliving_price_quote(self):
        binding, raw, now = self.material()
        binding['expires_at'] = (now + timedelta(hours=24)).isoformat()
        with self.assertRaisesRegex(StateError, 'pricing window'):
            build_activation_bundle(binding, raw, now=now)


if __name__ == '__main__':
    unittest.main()
