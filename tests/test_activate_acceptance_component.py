import base64
import copy
import json
import sys
import tempfile
import unittest
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / 'src'), str(ROOT / 'scripts'), str(ROOT / 'tests')]

import activate_acceptance_component as deploy
from factory_runtime.autonomy_contract import COMMISSIONING_ID, load_autonomy_operating_allowance
from factory_runtime.intake import IntakePlan
from factory_runtime.receipt_transport import receipt_plan_digest
from factory_state.dispatch import DispatchRequest
from factory_state.model import Lease
from prepare_acceptance_job import BINDING_FIELDS, PLAN_FIELDS, prepare
from prepare_acceptance_activation_bundle import build_activation_bundle
from test_prepare_acceptance_activation_bundle import ActivationBundleTests


def material():
    binding, raw, _ = ActivationBundleTests().material()
    document = json.loads(raw)
    now = load_autonomy_operating_allowance(ROOT).commissioning_starts_at + timedelta(seconds=1)
    binding.update(activation_id=COMMISSIONING_ID, starts_at=now.isoformat(),
                   expires_at=(now + timedelta(hours=1)).isoformat())
    document['lease']['expires_at'] = (now + timedelta(minutes=30)).isoformat()
    for payload in (document['capability_payload'], document['review_payload']):
        payload.update(issued_at=int(now.timestamp()), expires_at=int((now + timedelta(minutes=20)).timestamp()))
    plan = IntakePlan(document['factory_id'], document['task_id'], document['state'], document['state_version'],
        Lease(**{**document['lease'], 'expires_at': datetime.fromisoformat(document['lease']['expires_at'])}),
        DispatchRequest(**document['request']), document['capability_payload'], document['review_payload'])
    document['plan_digest'] = receipt_plan_digest(plan)
    raw, _ = prepare({k: binding[k] for k in BINDING_FIELDS}, {k: document[k] for k in PLAN_FIELDS},
        document['receipt_versions'], base64.b64decode(document['input_base64']),
        base64.b64decode(document['contract_base64']), now=now)
    return binding, raw, now, build_activation_bundle(binding, raw, now=now)


class ActivationDeploymentTests(unittest.TestCase):
    def test_iam_table_reference_matches_aws_resource_arn(self):
        template = json.loads((ROOT / deploy.COMPONENTS['builder'][1]).read_text())
        self.assertEqual(deploy.resolve({'Fn::GetAtt': ['RoleExecutions', 'Arn']}, template, {}),
            'arn:aws:dynamodb:ca-central-1:666730517561:table/tims-factory-role-executions')

    def test_exact_templates_publish_immutable_configs_and_scoped_iam(self):
        binding, _, _, bundle = material()
        for component in deploy.COMPONENTS:
            with self.subTest(component=component):
                baseline, proposed = deploy.render(component, bundle, binding)
                logical = deploy.COMPONENTS[component][2]
                self.assertEqual(baseline['Resources'][logical]['Properties']['Environment']['Variables'][deploy.COMPONENTS[component][4]], 'false')
                self.assertEqual(proposed['Resources'][logical]['Properties']['Environment']['Variables'][deploy.COMPONENTS[component][4]], 'true')
                self.assertIn('Description', proposed['Resources'][deploy.VERSIONS[component]]['Properties'])
                changed = {k for k in set(baseline['Resources']) | set(proposed['Resources'])
                           if baseline['Resources'].get(k) != proposed['Resources'].get(k)}
                expected = {logical, deploy.VERSIONS[component]}
                if component == 'builder':
                    expected.add('BuilderRole')
                    statements = proposed['Resources']['BuilderRole']['Properties']['Policies'][1]['Fn::If'][1]['PolicyDocument']['Statement']
                    self.assertEqual(next(s for s in statements if s['Sid'] == 'InvokePinnedCredentialFreeBroker')['Resource'], binding['broker_version_arn'])
                if component == 'controller':
                    expected.update(('ControllerRole', 'AcceptanceNoRetries'))
                    policies = proposed['Resources']['ControllerRole']['Properties']['Policies']
                    self.assertEqual(policies[-1]['PolicyDocument'], bundle['controller_policy'])
                    retry = proposed['Resources']['AcceptanceNoRetries']['Properties']
                    self.assertEqual((retry['MaximumRetryAttempts'], retry['MaximumEventAgeInSeconds']), (0, 60))
                self.assertEqual(changed, expected)

    def test_missing_authority_or_pending_gate_drift_prevents_render(self):
        binding, _, _, bundle = material()
        for changes in ({'contract_blockers': []}, {'activation_id': 'another'},
                        {'contract_blockers': bundle['contract_blockers'] + ['operating_contract_not_active']}):
            with self.subTest(changes=changes), self.assertRaises(RuntimeError):
                deploy.render('broker', {**bundle, **changes}, binding)

    def test_stale_scope_fails_before_mutation(self):
        binding, raw, now, bundle = material()
        _, proposed = deploy.render('broker', bundle, binding)
        plan = {'source_commit': binding['source_commit'], 'prepared_at': now.isoformat(),
            'component': 'broker', 'binding': binding, 'bundle': bundle,
            'job_base64': base64.b64encode(raw).decode(), 'template_sha256': deploy.sha(proposed),
            'before': {'parameters': {}}}
        with patch.object(deploy, 'source', return_value=binding['source_commit']), \
                patch.object(deploy, 'aws', return_value={'Account': deploy.ACCOUNT}) as aws, \
                patch.object(deploy, 'build_activation_bundle', side_effect=RuntimeError('scope expired')):
            with self.assertRaisesRegex(RuntimeError, 'scope expired'):
                deploy.checked(plan, live=True)
            self.assertEqual([c.args[:2] for c in aws.call_args_list], [('sts', 'get-caller-identity')])

    def test_uncertain_execution_is_not_replayed(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'attempt.json'
            path.write_text(json.dumps({'status': 'ATTEMPTED_RECONCILE_REQUIRED'}))
            with patch.object(deploy, 'aws') as aws, self.assertRaisesRegex(RuntimeError, 'single-attempt'):
                deploy.execute(path)
            aws.assert_not_called()

    def test_execution_journal_precedes_mutation_and_survives_timeout(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'attempt.json'
            plan = {'status': 'PREPARED_NOT_EXECUTED', 'component': 'broker',
                    'before': {'parameters': {}}, 'change_set_arn': 'change'}
            path.write_text(json.dumps(plan))
            def timeout(*args):
                self.assertEqual(json.loads(path.read_text())['status'], 'ATTEMPTED_RECONCILE_REQUIRED')
                raise TimeoutError('uncertain')
            with patch.object(deploy, 'checked', return_value=({}, {})), \
                    patch.object(deploy, 'snapshot', return_value=plan['before']), \
                    patch.object(deploy, 'verify_iam'), patch.object(deploy, 'change_checked'), \
                    patch.object(deploy, 'aws', side_effect=timeout) as aws:
                with self.assertRaises(TimeoutError):
                    deploy.execute(path)
                self.assertEqual(aws.call_count, 1)

    def test_wrong_artifact_source_hash_or_bucket_fails_closed(self):
        commit = 'a' * 40; code = b'x' * 32
        params = {'CodeSha256': base64.b64encode(code).decode(), 'ArtifactBucket': deploy.BUCKET,
            'ArtifactKey': f'factory-role-packages/{commit}/{code.hex()}.zip', 'ArtifactVersion': 'v1'}
        deploy.artifact('builder', params, commit)
        for changes in ({'ArtifactBucket': 'other'}, {'ArtifactVersion': 'null'}, {'CodeSha256': base64.b64encode(b'y' * 32).decode()}):
            with self.subTest(changes=changes), self.assertRaises(RuntimeError):
                deploy.artifact('builder', {**params, **changes}, commit)

    def test_extra_resource_code_change_or_wrong_replacement_is_rejected(self):
        changes = [{'ResourceChange': {'LogicalResourceId': name, 'Action': 'Modify',
            'Replacement': replacement, 'Scope': ['Properties'],
            'Details': [{'Target': {'Attribute': 'Properties', 'Name': prop}}]}}
            for name, replacement, prop in [('BrokerFunction', 'False', 'Environment'), ('BrokerVersion', 'True', 'Description')]]
        deploy.validate_changes('broker', changes)
        bad = copy.deepcopy(changes); bad[0]['ResourceChange']['Details'][0]['Target']['Name'] = 'Code'
        with self.assertRaises(RuntimeError):
            deploy.validate_changes('broker', bad)
        bad = copy.deepcopy(changes); bad[1]['ResourceChange']['Replacement'] = 'False'
        with self.assertRaises(RuntimeError):
            deploy.validate_changes('broker', bad)
        with self.assertRaises(RuntimeError):
            deploy.validate_changes('broker', changes + [changes[0]])


if __name__ == '__main__':
    unittest.main()
