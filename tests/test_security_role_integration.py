"""Role runtime integration; real signatures, simulated AWS and HTTPS only.

QA provenance remains a fixture here; this is not live acceptance evidence.
"""
import base64
from dataclasses import asdict
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from factory_runtime import pilot002_transport as wire
from factory_runtime.security_role_runtime import BoundedSecurityRoleRuntime
from factory_runtime.security_signing import IDENTITY
from factory_state.model import StateError
import test_security_authorization_integration as authorization_fixtures
import test_security_signing as signing_fixtures
from test_security_provider_claims import mock_aws
from test_pilot002_transport import Connection, Response


@unittest.skipIf(mock_aws is None,'Requires moto[dynamodb]')
class SecurityRoleIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.auth=authorization_fixtures.SecurityAuthorizationTests()
        self.auth.setUp();self.addCleanup(self.auth.doCleanups)
        self.signing=signing_fixtures.SecuritySigningTests()
        self.signing.setUp();self.addCleanup(self.signing.doCleanups)
        self.auth.keys[IDENTITY]=self.signing.keys[IDENTITY]
        self.auth.db.create_table(TableName='tims-factory-role-executions',
            KeySchema=[{'AttributeName':'PK','KeyType':'HASH'},{'AttributeName':'SK','KeyType':'RANGE'}],
            AttributeDefinitions=[{'AttributeName':k,'AttributeType':'S'} for k in ('PK','SK')],
            BillingMode='PAY_PER_REQUEST')
        def meta(service):
            return SimpleNamespace(endpoint_url=f'https://{service}.ca-central-1.amazonaws.com',
                config=SimpleNamespace(retries={'total_max_attempts':1}))
        kms=SimpleNamespace(meta=meta('kms'),get_public_key=self.signing.get_public_key,sign=self.signing.sign)
        sts=SimpleNamespace(meta=meta('sts'),get_caller_identity=self.signing.get_caller_identity)
        self.runtime=BoundedSecurityRoleRuntime(backend=self.auth.backend,kms=kms,sts=sts,
            execution_table='tims-factory-role-executions',enabled=True)
        self.event={'schema_version':'1.0','factory_id':self.auth.state.factory_id,
            'task_id':self.auth.state.task_id,'worker_id':'bounded-security-controller',
            'request':asdict(self.auth.request),'dispatch_id':self.auth.dispatch,
            'input_base64':base64.b64encode(self.auth.backend.prepared.input_bytes).decode()}

    def test_runtime_signs_once_and_replay_does_not_send_again(self):
        self.auth.hold()
        connection=Connection(Response(self.auth.fixture.response))
        with patch.object(wire.http.client,'HTTPSConnection',return_value=connection) as network:
            result=self.runtime.handle(self.event)
            replay=self.runtime.handle(self.event)
        self.assertEqual(result,replay)
        self.assertEqual(network.call_count,1)
        self.assertEqual(self.signing.calls,1)
        self.assertEqual(self.auth.fixture.claims.row()['status'],{'S':'COMPLETE'})

    def test_wrong_signing_custody_prevents_credentials_and_provider_send(self):
        self.auth.hold();self.signing.wrong=True
        with patch.object(wire.http.client,'HTTPSConnection') as network:
            with self.assertRaises(StateError):self.runtime.handle(self.event)
        network.assert_not_called();self.auth.fixture.credential.assert_not_called()
        self.assertEqual(self.signing.calls,0)
        self.assertEqual(self.auth.fixture.claims.row()['status'],{'S':'RESERVED'})

    def test_transport_uncertainty_cannot_repeat_through_role_service(self):
        self.auth.hold()
        with patch.object(wire.http.client,'HTTPSConnection',
                return_value=Connection(error=TimeoutError('fixture'))) as network:
            with self.assertRaises(StateError):self.runtime.handle(self.event)
            with self.assertRaises(StateError):self.runtime.handle(self.event)
        self.assertEqual(network.call_count,1)
        self.assertEqual(self.signing.calls,0)
        self.assertEqual(self.auth.fixture.claims.row()['status'],{'S':'STARTED'})


if __name__ == '__main__':unittest.main()
