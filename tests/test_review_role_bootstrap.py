import json
import os
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

from factory_runtime.review_role_probe import IDENTITIES, probe, handler, validate
from factory_state.kms_signer import ALGORITHM
from factory_state.signers import public_key_der
from factory_state.model import StateError
from scripts.scope_dispatch_canary import fixture_keys, sign
from prepare_review_role_bootstrap import render
from verify_candidate_qa import verify

ROOT = Path(__file__).resolve().parents[1]
NOW = datetime(2026, 10, 2, 20, tzinfo=timezone.utc)
KEY = 'arn:aws:kms:ca-central-1:666730517561:key/11111111-1111-1111-1111-111111111111'
EVENT = {'kind': 'review_role_identity_probe', 'source_commit': 'a'*40, 'nonce': 'b'*32}


class BootstrapTests(unittest.TestCase):
    def test_both_isolated_identities_sign_only_fixed_challenges(self):
        with tempfile.TemporaryDirectory() as directory:
            keys, private = fixture_keys(directory, tuple(IDENTITIES.values()))
            for role, identity in IDENTITIES.items():
                class Sts:
                    def get_caller_identity(self):
                        return {'Account': '666730517561', 'Arn': 'arn:aws:sts::666730517561:assumed-role/tims-factory-review-'+role+'/probe'}
                class Kms:
                    def get_public_key(self, **kwargs):
                        return {'KeyId': KEY, 'KeyUsage': 'SIGN_VERIFY', 'KeySpec': 'ECC_NIST_EDWARDS25519',
                                'SigningAlgorithms': [ALGORITHM], 'PublicKey': public_key_der(keys[identity])}
                    def sign(self, **kwargs):
                        self_request = {'KeyId': KEY, 'MessageType': 'RAW', 'SigningAlgorithm': ALGORITHM}
                        assert all(kwargs[k] == v for k, v in self_request.items())
                        return {'KeyId': KEY, 'SigningAlgorithm': ALGORITHM,
                            'Signature': sign(json.loads(kwargs['Message']), private[identity], directory)}
                result = probe(EVENT, role=role, commit='a'*40, flag='false', key_arn=KEY,
                               kms=Kms(), sts=Sts(), now=NOW)
                self.assertEqual(result['payload']['identity'], identity)
                self.assertEqual(result['model_calls'], 0)
                self.assertFalse(result['scope_approval'])

    def test_wrong_cloud_identity_cannot_reach_key(self):
        class Sts:
            def get_caller_identity(self): return {'Account': '666730517561', 'Arn': 'root'}
        with self.assertRaises(StateError):
            probe(EVENT, role='qa', commit='a'*40, flag='false', key_arn=KEY, kms=None, sts=Sts(), now=NOW)

    def test_operational_events_flags_and_wrong_bindings_are_rejected(self):
        args = dict(role='qa', commit='a'*40, flag='false', key_arn=KEY)
        for event in ({**EVENT, 'kind': 'role_result'}, {**EVENT, 'candidate': 'anything'},
                      {**EVENT, 'nonce': 'bad'}, {**EVENT, 'source_commit': 'c'*40}):
            with self.assertRaises(StateError): validate(event, **args)
        for key, value in [('role', 'builder'), ('flag', 'true'), ('flag', None), ('key_arn', KEY.replace('ca-central-1', 'us-east-1'))]:
            with self.assertRaises(StateError): validate(EVENT, **{**args, key: value})

    def test_handler_rejects_before_aws_clients(self):
        with tempfile.TemporaryDirectory() as directory:
            (Path(directory)/'BUILD.json').write_text(json.dumps({'source_commit': 'a'*40}))
            with patch.dict(os.environ, {'LAMBDA_TASK_ROOT': directory, 'FACTORY_REVIEW_ROLE': 'qa',
                    'FACTORY_REVIEW_KEY_ARN': KEY, 'FACTORY_OPERATIONAL_EXECUTION_ENABLED': 'false'}, clear=True):
                with self.assertRaises(StateError): handler({'kind': 'dispatch'}, None)

    def test_template_grants_only_own_key_and_logs_with_no_live_controls(self):
        template = render()
        self.assertEqual(len(template['Resources']), 12)
        for label, role in [('Qa', 'qa'), ('Security', 'security')]:
            resources = template['Resources']
            key = resources[label+'Key']
            self.assertEqual(key['DeletionPolicy'], 'Retain')
            deny = key['Properties']['KeyPolicy']['Statement'][1]
            self.assertEqual(deny['Condition']['ArnNotEquals']['aws:PrincipalArn'],
                             'arn:aws:iam::666730517561:role/tims-factory-review-'+role)
            policies = resources[label+'Role']['Properties']['Policies']
            statements = policies[0]['PolicyDocument']['Statement']
            self.assertEqual({a for s in statements for a in s['Action']},
                             {'kms:GetPublicKey','kms:Sign','logs:CreateLogStream','logs:PutLogEvents'})
            for s in statements[:2]: self.assertEqual(s['Resource'], {'Fn::GetAtt':[label+'Key','Arn']})
            self.assertEqual(resources[label+'Function']['Properties']['Environment']['Variables']
                ['FACTORY_OPERATIONAL_EXECUTION_ENABLED'], 'false')
        self.assertNotIn('AWS::Lambda::Permission', json.dumps(template))
        self.assertNotIn('AWS::Scheduler', json.dumps(template))
        path = ROOT/'infra/roles/review-bootstrap.cloudformation.json'
        self.assertEqual(json.loads(path.read_bytes()), template)

    def test_pinned_candidate_passes_extended_offline_qa(self):
        result = verify(ROOT)
        self.assertEqual(result['required_tests_passed'], 11)
        self.assertEqual(result['supplemental_process_runs'], 91)
        self.assertEqual(result['state_writes'], 0)


if __name__ == '__main__': unittest.main()
