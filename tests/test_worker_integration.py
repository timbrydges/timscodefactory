"""Real signature checks and optional DynamoDB worker failure/restart integration."""
import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from scripts.scope_dispatch_canary import fixture_keys
from factory_state.signers import load_trusted_signers, public_key_der
from factory_state.scope import SignedScopeStore
from factory_state.model import StateError
from test_dispatch_ledger import NOW

try:
    import boto3
    from moto import mock_aws
except ImportError:
    mock_aws = None


class SignerEnrollmentTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / 'registry.json'
        self.keys, _ = fixture_keys(self.directory.name)
        self.document = {'schema_version': '1.0', 'enabled': True, 'signers': [
            {'identity': identity, 'public_key_pem': key.decode(),
             'fingerprint': 'sha256:' + hashlib.sha256(public_key_der(key)).hexdigest(),
             'enrollment_commit': 'a' * 40, 'not_before': int(NOW.timestamp()) - 1,
             'expires_at': int(NOW.timestamp()) + 300, 'revoked': False}
            for identity, key in self.keys.items()]}

    def load(self):
        self.path.write_text(json.dumps(self.document))
        return load_trusted_signers(self.path, now=NOW)

    def test_valid_enrollment_and_revocation(self):
        self.assertEqual(self.load(), self.keys)
        self.document['signers'][1]['revoked'] = True
        self.assertEqual(set(self.load()), {'tim_brydges'})

    def test_duplicate_material_cannot_impersonate_independence(self):
        self.document['signers'][1].update({k: self.document['signers'][0][k]
                                          for k in ('public_key_pem', 'fingerprint')})
        with self.assertRaises(StateError): self.load()
        with self.assertRaises(StateError):
            SignedScopeStore('table', None, {'tim_brydges': self.keys['tim_brydges'],
                'independent_inspector_service': self.keys['tim_brydges']})

    def test_disabled_expired_and_unpinned_enrollment(self):
        self.document['enabled'] = False
        with self.assertRaises(StateError): self.load()
        self.document['enabled'] = True
        self.document['signers'][0]['expires_at'] = int(NOW.timestamp())
        self.assertNotIn('tim_brydges', self.load())
        self.document['signers'][1]['enrollment_commit'] = 'main'
        with self.assertRaises(StateError): self.load()

    def test_key_algorithm_and_fingerprint_are_pinned(self):
        with self.assertRaises(StateError): public_key_der(b'not a public key')
        self.document['signers'][0]['fingerprint'] = 'sha256:' + '0' * 64
        with self.assertRaises(StateError): self.load()


@unittest.skipIf(mock_aws is None, 'Install moto[dynamodb]==5.1.12 for integration proof')
class WorkerIntegrationTests(unittest.TestCase):
    def test_signature_pause_crash_and_restart_paths(self):
        from scripts.worker_dispatch_canary import run
        with mock_aws():
            client = boto3.client('dynamodb', region_name='ca-central-1')
            client.create_table(TableName='worker-state',
                KeySchema=[{'AttributeName': 'PK', 'KeyType': 'HASH'}, {'AttributeName': 'SK', 'KeyType': 'RANGE'}],
                AttributeDefinitions=[{'AttributeName': x, 'AttributeType': 'S'} for x in ('PK', 'SK')],
                BillingMode='PAY_PER_REQUEST')
            evidence = run(client, 'worker-state', '123-1', 'a' * 40, now=NOW)
            self.assertEqual(len(evidence['checks']), 8)
            self.assertEqual(evidence['model_calls'], 0)
            self.assertFalse(evidence['continuous_worker_activated'])
