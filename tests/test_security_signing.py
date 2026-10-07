import base64
from dataclasses import asdict
import json
import tempfile
from types import SimpleNamespace
import unittest

from factory_runtime.security_signing import (SecurityAllowanceSigner, SecurityResultSigner,
    SECURITY_KEY, SECURITY_ROLE, IDENTITY)
from factory_runtime.security_role_runtime import BoundedSecurityRoleRuntime
from factory_runtime.review_signing import KEYS, ROLES
from factory_state.dispatch import DynamoDBDispatchStore
from factory_state.kms_signer import ALGORITHM
from factory_state.model import StateError
from factory_state.signers import public_key_der
from scripts.scope_dispatch_canary import fixture_keys, sign
from test_security_provider_scope import fixture, NOW
import test_security_provider_protocol as protocol_fixtures


class SecuritySigningTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.keys,self.private=fixture_keys(self.temp.name,('tim_brydges',IDENTITY))
        self.identity=IDENTITY;self.key=SECURITY_KEY;self.role=SECURITY_ROLE
        self.calls=0;self.wrong=False

    def get_caller_identity(self):
        role='wrong' if self.wrong else self.role
        return {'Account':'666730517561','Arn':f'arn:aws:sts::666730517561:assumed-role/{role}/fixture'}

    def get_public_key(self, **kwargs):
        self.assertEqual(kwargs['KeyId'],self.key)
        return {'KeyId':self.key,'KeySpec':'ECC_NIST_EDWARDS25519','KeyUsage':'SIGN_VERIFY',
            'SigningAlgorithms':[ALGORITHM],'PublicKey':public_key_der(self.keys[self.identity])}

    def sign(self, **kwargs):
        self.calls+=1
        return {'KeyId':self.key,'SigningAlgorithm':ALGORITHM,
            'Signature':sign(json.loads(kwargs['Message']),self.private[self.identity],self.temp.name)}

    def context(self):
        return dict(kms=self,sts=self,key_loader=lambda _:self.keys,clock=lambda:NOW,enabled=True)

    def result(self):
        scope,*_=fixture()
        signer=SecurityResultSigner(request=scope.request,dispatch_id='d'*64,**self.context())
        payload={'kind':'role_result','factory_id':'tims-software-factory','task_id':'bounded-review-004',
            'binding':DynamoDBDispatchStore._binding(scope.request),'dispatch_id':'d'*64,
            'producer_identity':IDENTITY,'output_digest':'sha256:'+'f'*64,
            'issued_at':int(NOW.timestamp()),'expires_at':int(NOW.timestamp())+300}
        return signer,payload

    def test_result_custody_preflight_and_single_signature(self):
        signer,payload=self.result()
        self.assertEqual(signer.preflight(),IDENTITY);self.assertEqual(self.calls,0)
        self.assertEqual(len(signer.sign(payload,now=NOW)),64)
        with self.assertRaises(StateError):signer.sign(payload,now=NOW)
        self.assertEqual(self.calls,1)

    def test_wrong_session_or_revoked_enrollment_blocks_signing(self):
        signer,payload=self.result();self.wrong=True
        with self.assertRaises(StateError):signer.preflight()
        self.wrong=False;self.keys.pop(IDENTITY)
        with self.assertRaises(StateError):signer.sign(payload,now=NOW)
        self.assertEqual(self.calls,0)

    def test_owner_adapter_signs_only_exact_security_allowance(self):
        self.identity='tim_brydges';self.key=KEYS['owner'];self.role=ROLES['owner']
        scope,price,ready,payload=fixture()
        signer=SecurityAllowanceSigner(scope=scope,pricing=price,readiness=ready,**self.context())
        with self.assertRaises(StateError):signer.sign({**payload,'retries':1},now=NOW)
        self.assertEqual(len(signer.sign(payload,now=NOW)),64)

    def test_runtime_event_rejects_controller_or_job_substitution(self):
        fixture=protocol_fixtures.SecurityProtocolTests();fixture.setUp();prepared=fixture.prepared
        event={'schema_version':'1.0','factory_id':'tims-software-factory','task_id':'bounded-review-004',
            'worker_id':'bounded-security-controller','request':asdict(prepared.scope.request),
            'input_base64':base64.b64encode(prepared.input_bytes).decode(),'dispatch_id':'d'*64}
        BoundedSecurityRoleRuntime.validate_event(prepared,event)
        for change in ({'worker_id':'bounded-review-controller'},{'input_base64':'eA=='},
                       {'dispatch_id':'wrong'},{'enabled':True}):
            with self.assertRaises(StateError):
                BoundedSecurityRoleRuntime.validate_event(prepared,{**event,**change})

    def test_runtime_defaults_disabled_before_event_or_signer_io(self):
        import test_security_provider_backend as backend_fixtures
        if backend_fixtures.mock_aws is None:self.skipTest('Requires moto[dynamodb]')
        fixture=backend_fixtures.SecurityBackendTests();fixture.setUp();self.addCleanup(fixture.doCleanups)
        def client(service):
            return SimpleNamespace(meta=SimpleNamespace(endpoint_url=f'https://{service}.ca-central-1.amazonaws.com',
                config=SimpleNamespace(retries={'total_max_attempts':1})))
        runtime=BoundedSecurityRoleRuntime(backend=fixture.backend,kms=client('kms'),sts=client('sts'),
            execution_table='tims-factory-role-executions')
        with self.assertRaisesRegex(StateError,'disabled'):runtime.handle({})
        fixture.credential.assert_not_called()


if __name__ == '__main__':unittest.main()
