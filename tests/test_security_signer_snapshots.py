from datetime import timedelta
from pathlib import Path
import tempfile
import unittest

from factory_runtime.security_deployment import signer_loader
from factory_runtime.worker import digest
from factory_state.model import StateError
from factory_state.scope import canonical
from factory_state.signers import public_key_der
from scripts.scope_dispatch_canary import fixture_keys
from test_security_provider_scope import NOW


class SnapshotTests(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory();self.addCleanup(temp.cleanup);self.root=Path(temp.name)
        self.keys,_=fixture_keys(temp.name,('tim_brydges','product_spec_reviewer_service',
            'deep_security_reviewer_service','qa_engineer_service'))
        self.env={}

    def write(self, identities, *, historical=False):
        doc={'schema_version':'1.0','enabled':True,'signers':[{
            'identity':i,'public_key_pem':self.keys[i].decode(),
            'fingerprint':digest(public_key_der(self.keys[i])),'enrollment_commit':'a'*40,
            'not_before':int(NOW.timestamp())-3600,'expires_at':int(NOW.timestamp())+3600,
            'revoked':False} for i in identities]}
        raw=canonical(doc)
        name='SECURITY_QA_SIGNERS.json' if historical else 'SECURITY_SIGNERS.json'
        pin='FACTORY_SECURITY_QA_SIGNERS_DIGEST' if historical else 'FACTORY_SECURITY_SIGNERS_DIGEST'
        (self.root/name).write_bytes(raw);self.env[pin]=digest(raw)

    def test_current_snapshot_is_immutable_but_enrollment_time_is_rechecked(self):
        self.write(tuple(self.keys))
        load=signer_loader(self.root,self.env)
        (self.root/'SECURITY_SIGNERS.json').write_bytes(b'{}')
        self.assertEqual(load(NOW),self.keys)
        with self.assertRaises(StateError):load(NOW+timedelta(hours=2))
        with self.assertRaises(StateError):signer_loader(self.root,self.env)

    def test_historical_snapshot_cannot_supply_owner_authority(self):
        self.write(('qa_engineer_service',),historical=True)
        load=signer_loader(self.root,self.env,historical=True)
        self.assertEqual(set(load(NOW)),{'qa_engineer_service'})
        self.write(('qa_engineer_service','tim_brydges'),historical=True)
        with self.assertRaises(StateError):signer_loader(self.root,self.env,historical=True)(NOW)

    def test_qa_only_snapshot_cannot_enable_current_security_signing(self):
        self.write(('qa_engineer_service',))
        with self.assertRaises(StateError):signer_loader(self.root,self.env)(NOW)


if __name__ == '__main__':unittest.main()
