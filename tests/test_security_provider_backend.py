"""Offline orchestration tests; mocked authority is never runtime evidence."""
from dataclasses import replace
import hashlib
import json
import unittest
from unittest.mock import Mock, patch

from factory_runtime import pilot002_transport as wire
from factory_runtime.security_provider_backend import SecurityProviderBackend
from factory_runtime.security_provider_protocol import prepare, job_input
from factory_runtime.security_provider_transport import SecurityProviderTransport
from factory_runtime.review_verdict import PinnedPythonTestEvidence
from factory_runtime.worker import digest
from factory_state.model import StateError
from factory_state.scope import canonical
import test_security_provider_protocol as protocol_fixtures
import test_security_provider_claims as claim_fixtures
from test_security_provider_claims import mock_aws, NOW
from test_pilot002_transport import Connection, Response, AWS


@unittest.skipIf(mock_aws is None, 'Requires moto[dynamodb]')
class SecurityBackendTests(unittest.TestCase):
    def setUp(self):
        claims = claim_fixtures.SecurityClaimTests(); claims.setUp(); self.addCleanup(claims.doCleanups)
        self.claims = claims
        codec = protocol_fixtures.SecurityProtocolTests(); codec.setUp()
        old = codec.prepared.scope
        proof = canonical({'source_commit':old.binding.qa.source_commit,
            'candidate_commit':old.binding.qa.candidate_commit,'observed_at':NOW.isoformat(),
            'runtime':'python3.12-linux','python_version':'3.12.15',
            'files':{p:hashlib.sha256(v.encode()).hexdigest() for p,v in codec.files.items()},
            'exit_code':0,'credentials_in_environment':False,'stdout':'',
            'stderr':'test_fixture ... ok\n\nRan 1 tests in 0.001s\n\nOK\n'})
        binding = replace(old.binding, qa=replace(old.binding.qa, test_evidence_digest=digest(proof)))
        raw = job_input(binding, codec.files)
        binding = replace(binding, input_digest=digest(raw))
        request = replace(old.request, input_digest=digest(raw))
        self.prepared = prepare(binding=binding, request=request, files=codec.files, input_bytes=raw)
        evidence = PinnedPythonTestEvidence(binding.qa, proof, codec.files, test_count=1, clock=lambda:NOW)
        self.credential = Mock(return_value=AWS)
        self.backend = SecurityProviderBackend(prepared=self.prepared, envelope={},
            pricing={'input_micro_usd_per_million':3000000,'output_micro_usd_per_million':15000000,
                     'input_token_bound':32768}, readiness={}, states=Mock(), ledger=Mock(),
            claims=claims.store, key_loader=Mock(), test_evidence=evidence,
            verify_prerequisites=Mock(return_value=True), clock=lambda:NOW,
            load_credential=self.credential)
        self.state = Mock(); self.request = request
        self.report = {**json.loads(self.prepared.expected_output), 'verdict':'REJECTED',
                       'rationale':'Fixture risk.', 'findings':[]}
        self.response = canonical({'stopReason':'end_turn','output':{'message':{
            'role':'assistant','content':[{'text':canonical(self.report).decode()}]}},
            'usage':{'inputTokens':100,'outputTokens':50,'totalTokens':150}})

    def execute(self):
        return self.backend.execute(self.state, self.request, dispatch_id=self.claims.dispatch,
                                    input_bytes=self.prepared.input_bytes)

    def authorize_fixture(self):
        self.backend.check_activation = Mock(return_value=self.claims.grant)
        self.backend._started = Mock()
        self.backend.reserve(self.state, self.request, dispatch_id=self.claims.dispatch, now=NOW)

    def test_default_disabled_before_credentials_or_network(self):
        with patch.object(wire.http.client, 'HTTPSConnection') as network:
            with self.assertRaises(StateError): self.execute()
        self.credential.assert_not_called(); network.assert_not_called()

    def test_claim_precedes_credentials_and_rejected_result_completes_once(self):
        self.authorize_fixture()
        def credential():
            self.assertEqual(self.claims.row()['status'], {'S':'STARTED'})
            return AWS
        self.credential.side_effect = credential
        connection = Connection(Response(self.response))
        with patch.object(wire.http.client, 'HTTPSConnection', return_value=connection) as network:
            self.assertEqual(json.loads(self.execute()), self.report)
            with self.assertRaises(StateError): self.execute()
        self.assertEqual(network.call_count, 1); self.assertEqual(self.credential.call_count, 1)
        self.assertEqual(self.claims.row()['status'], {'S':'COMPLETE'})
        self.assertEqual(self.claims.row()['reservation_status'], {'S':'HELD'})

    def test_failed_credential_consumes_send_without_network(self):
        self.authorize_fixture(); self.credential.side_effect = RuntimeError('private')
        with patch.object(wire.http.client, 'HTTPSConnection') as network:
            with self.assertRaises(StateError) as error: self.execute()
            with self.assertRaises(StateError): self.execute()
        self.assertNotIn('private', str(error.exception)); network.assert_not_called()
        self.assertEqual(self.credential.call_count, 1)
        self.assertEqual(self.claims.row()['status'], {'S':'STARTED'})

    def test_authority_change_after_credential_blocks_send(self):
        self.authorize_fixture()
        self.backend.check_activation.side_effect = [self.claims.grant, StateError('expired')]
        with patch.object(wire.http.client, 'HTTPSConnection') as network:
            with self.assertRaises(StateError): self.execute()
        network.assert_not_called()
        self.assertEqual(self.claims.row()['status'], {'S':'STARTED'})

    def test_transport_route_and_latch(self):
        connection = Connection(Response(self.response))
        with patch.object(wire.http.client, 'HTTPSConnection', return_value=connection) as network:
            transport = SecurityProviderTransport(self.prepared, enabled=True)
            args = dict(request_bytes=self.prepared.scope.request_bytes, credential=AWS,
                        expected_request_digest=digest(self.prepared.scope.request_bytes))
            transport.send_once(**args)
            with self.assertRaises(StateError): transport.send_once(**args)
        self.assertEqual(network.call_args.args[0], 'bedrock-runtime.ca-central-1.amazonaws.com')
        self.assertEqual(network.call_count, 1)


if __name__ == '__main__': unittest.main()
